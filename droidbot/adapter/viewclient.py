# Copyright (C) 2012-2015  Diego Torres Milano
# Copyright (C) 2016 Cuckoo Foundation.
# Copyright (C) 2016 Yuanchun Li.
import logging
import re
import socket
import sys
import time
import types
import xml.parsers.expat
from adb import ADB
from adapter import Adapter
from viewclient_utils import _nd, _nh, _ns, obtainPxPy, obtainVwVh, obtainVxVy, Window

VIEW_SERVER_HOST = 'localhost'
VIEW_SERVER_PORT = 4939

# some constants for the attributes
VIEW_CLIENT_TOUCH_WORKAROUND_ENABLED = False
ID_PROPERTY = 'mID'
ID_PROPERTY_UI_AUTOMATOR = 'uniqueId'
TEXT_PROPERTY = 'text:mText'
TEXT_PROPERTY_API_10 = 'mText'
TEXT_PROPERTY_UI_AUTOMATOR = 'text'
WS = u"\xfe"  # the whitespace replacement char for TEXT_PROPERTY
TAG_PROPERTY = 'getTag()'
LEFT_PROPERTY = 'layout:mLeft'
LEFT_PROPERTY_API_8 = 'mLeft'
TOP_PROPERTY = 'layout:mTop'
TOP_PROPERTY_API_8 = 'mTop'
WIDTH_PROPERTY = 'layout:getWidth()'
WIDTH_PROPERTY_API_8 = 'getWidth()'
HEIGHT_PROPERTY = 'layout:getHeight()'
HEIGHT_PROPERTY_API_8 = 'getHeight()'
GET_VISIBILITY_PROPERTY = 'getVisibility()'
LAYOUT_TOP_MARGIN_PROPERTY = 'layout:layout_topMargin'
IS_FOCUSED_PROPERTY_UI_AUTOMATOR = 'focused'
IS_FOCUSED_PROPERTY = 'focus:isFocused()'
IS_ENABLED_PROPERTY_UI_AUTOMATOR = 'enabled'
IS_ENABLED_PROPERTY = 'isEnabled()'

# visibility
VISIBLE = 0x0
INVISIBLE = 0x4
GONE = 0x8

ID_RE = re.compile('id/([^/]*)(/(\d+))?')


class View:
    """
    View class
    """

    @classmethod
    def __copy(cls, view):
        """
        Copy constructor
        """
        return cls(view.map, view.version, view.windowId)

    def __init__(self, attributes, device, useUiAutomator, windowId=None):
        """
        Constructor
        @type attributes: map
        @param attributes: the map containing the (attribute, value) pairs
        @type device: Device
        @param device: the device containing this View
        @type useUiAutomator: boolean
        @param useUiAutomator: whether the view is dumped using UIAutomator
        """
        self.logger = logging.getLogger("ViewClient.View")
        self.attributes = attributes
        """ The map that contains the C{attr},C{value} pairs """
        self.adb = device.adb
        """ adb connection to device """
        # """ viewclient connected to device """
        self.children = []
        """ The children of this View """
        self.parent = None
        """ The parent of this View """
        self.currentFocus = None
        """ The current focus """
        self.windowId = windowId
        """ The window this view resides """
        version = device.get_sdk_version()
        self.version = version
        """ API version number """
        self.uiScrollable = None
        """ If this is a scrollable View this keeps the L{UiScrollable} object """
        self.target = False
        """ Is this a touch target zone """
        self.useUiAutomator = useUiAutomator
        """ Whether to use UIAutomator or ViewServer """

        self.idProperty = ID_PROPERTY
        self.textProperty = TEXT_PROPERTY
        self.tagProperty = TAG_PROPERTY
        self.leftProperty = LEFT_PROPERTY
        self.topProperty = TOP_PROPERTY
        self.widthProperty = WIDTH_PROPERTY
        self.heightProperty = HEIGHT_PROPERTY
        self.isFocusedProperty = IS_FOCUSED_PROPERTY
        self.isEnabledProperty = IS_ENABLED_PROPERTY

        if version >= 16 and self.useUiAutomator:
            self.idProperty = ID_PROPERTY_UI_AUTOMATOR
            self.textProperty = TEXT_PROPERTY_UI_AUTOMATOR
            self.isFocusedProperty = IS_FOCUSED_PROPERTY_UI_AUTOMATOR
            self.isEnabledProperty = IS_ENABLED_PROPERTY_UI_AUTOMATOR
        elif version == 10:
            self.textProperty = TEXT_PROPERTY_API_10
        elif 7 <= version < 10:
            self.textProperty = TEXT_PROPERTY_API_10
            self.leftProperty = LEFT_PROPERTY_API_8
            self.topProperty = TOP_PROPERTY_API_8
            self.widthProperty = WIDTH_PROPERTY_API_8
            self.heightProperty = HEIGHT_PROPERTY_API_8
        elif 0 < version < 7:
            self.textProperty = TEXT_PROPERTY_API_10

        try:
            if self.isScrollable():
                self.uiScrollable = UiScrollable(self)
        except AttributeError:
            pass

    def __getitem__(self, key):
        return self.attributes[key]

    def __getattr__(self, name):
        # NOTE:
        # I should try to see if 'name' is a defined method
        # but it seems that if I call locals() here an infinite loop is entered

        if self.attributes.has_key(name):
            r = self.attributes[name]
        elif self.attributes.has_key(name + '()'):
            # the method names are stored in the map with their trailing '()'
            r = self.attributes[name + '()']
        elif name.count("_") > 0:
            mangledList = self.allPossibleNamesWithColon(name)
            mangledName = self.intersection(mangledList, self.attributes.keys())
            if len(mangledName) > 0 and self.attributes.has_key(mangledName[0]):
                r = self.attributes[mangledName[0]]
            else:
                # Default behavior
                raise AttributeError, name
        elif name.startswith('is'):
            # try removing 'is' prefix
            suffix = name[2:].lower()
            if self.attributes.has_key(suffix):
                r = self.attributes[suffix]
            else:
                # Default behavior
                raise AttributeError, name
        elif name.startswith('get'):
            # try removing 'get' prefix
            suffix = name[3:].lower()
            if self.attributes.has_key(suffix):
                r = self.attributes[suffix]
            else:
                # Default behavior
                raise AttributeError, name
        elif name == 'getResourceId':
            if self.attributes.has_key('resource-id'):
                r = self.attributes['resource-id']
            else:
                # Default behavior
                raise AttributeError, name
        else:
            # Default behavior
            raise AttributeError, name

        if r == 'true':
            r = True
        elif r == 'false':
            r = False

        # this should not cached in some way
        def innerMethod():
            return r

        innerMethod.__name__ = name

        # this should work, but then there's problems with the arguments of innerMethod
        # even if innerMethod(self) is added
        # setattr(View, innerMethod.__name__, innerMethod)
        # setattr(self, innerMethod.__name__, innerMethod)

        return innerMethod

    def getClass(self):
        """
        Gets the L{View} class
        @return:  the L{View} class or C{None} if not defined
        """
        try:
            return self.attributes['class']
        except:
            return None

    def getId(self):
        """
        Gets the L{View} Id
        @return: the L{View} C{Id} or C{None} if not defined
        @see: L{getUniqueId()}
        """
        try:
            return self.attributes['resource-id']
        except:
            pass

        try:
            return self.attributes[self.idProperty]
        except:
            return None

    def getContentDescription(self):
        """
        Gets the content description.
        """
        try:
            return self.attributes['content-desc']
        except:
            return None

    def getTag(self):
        """
        Gets the tag.
        """
        try:
            return self.attributes[self.tagProperty]
        except:
            return None

    def getParent(self):
        """
        Gets the parent.
        """
        return self.parent

    def getChildren(self):
        """
        Gets the children of this L{View}.
        """
        return self.children

    def getText(self):
        """
        Gets the text attribute.
        @return: the text attribute or C{None} if not defined
        """
        try:
            return self.attributes[self.textProperty]
        except Exception:
            return None

    def getHeight(self):
        """
        Gets the height.
        """
        if self.useUiAutomator:
            return self.attributes['bounds'][1][1] - self.attributes['bounds'][0][1]
        else:
            try:
                return int(self.attributes[self.heightProperty])
            except:
                return 0

    def getWidth(self):
        """
        Gets the width.
        """
        if self.useUiAutomator:
            return self.attributes['bounds'][1][0] - self.attributes['bounds'][0][0]
        else:
            try:
                return int(self.attributes[self.widthProperty])
            except:
                return 0

    def getUniqueId(self):
        """
        Gets the unique Id of this View.
        @see: L{ViewClient.__parseAttrs()} for a discussion on B{Unique Ids}
        """
        try:
            return self.attributes['uniqueId']
        except:
            return None

    def getVisibility(self):
        """
        Gets the View visibility
        """
        try:
            if self.attributes[GET_VISIBILITY_PROPERTY] == 'VISIBLE':
                return VISIBLE
            elif self.attributes[GET_VISIBILITY_PROPERTY] == 'INVISIBLE':
                return INVISIBLE
            elif self.attributes[GET_VISIBILITY_PROPERTY] == 'GONE':
                return GONE
            else:
                return -2
        except:
            return -1

    def getX(self):
        """
        Gets the View X coordinate
        """
        return self.getXY()[0]

    def __getX(self):
        """
        Gets the View X coordinate
        """
        x = 0
        if self.useUiAutomator:
            x = self.attributes['bounds'][0][0]
        else:
            try:
                if GET_VISIBILITY_PROPERTY in self.attributes and self.attributes[GET_VISIBILITY_PROPERTY] == 'VISIBLE':
                    _x = int(self.attributes[self.leftProperty])
                    x += _x
            except:
                self.logger.warning("View %s has no '%s' property" % (self.getId(), self.leftProperty))
        return x

    def __getY(self):
        """
        Gets the View Y coordinate
        """
        y = 0
        if self.useUiAutomator:
            y = self.attributes['bounds'][0][1]
        else:
            try:
                if GET_VISIBILITY_PROPERTY in self.attributes and self.attributes[GET_VISIBILITY_PROPERTY] == 'VISIBLE':
                    _y = int(self.attributes[self.topProperty])
                    y += _y
            except:
                self.logger.warning("View %s has no '%s' property" % (self.getId(), self.topProperty))
        return y

    def getY(self):
        """
        Gets the View Y coordinate
        """
        return self.getXY()[1]

    def getXY(self, debug=False):
        """
        Returns the I{screen} coordinates of this C{View}.

        WARNING: Don't call self.getX() or self.getY() inside this method
        or it will enter an infinite loop

        @return: The I{screen} coordinates of this C{View}
        """
        self.logger.debug("getXY(%s %s ## %s)" % (self.getClass(), self.getId(), self.getUniqueId()))

        x = self.__getX()
        y = self.__getY()
        if self.useUiAutomator:
            return x, y

        parent = self.parent
        self.logger.debug("   getXY: x=%s y=%s parent=%s" % (x, y, parent.getUniqueId() if parent else "None"))
        hx = 0
        ''' Hierarchy accumulated X '''
        hy = 0
        ''' Hierarchy accumulated Y '''

        self.logger.debug("   getXY: not using UiAutomator, calculating parent coordinates")
        while parent is not None:
            self.logger.debug("      getXY: parent: %s %s <<<<" % (parent.getClass(), parent.getId()))
            # if SKIP_CERTAIN_CLASSES_IN_GET_XY_ENABLED:
            #     if parent.getClass() in [ 'com.android.internal.widget.ActionBarView',
            #                        'com.android.internal.widget.ActionBarContextView',
            #                        'com.android.internal.view.menu.ActionMenuView',
            #                        'com.android.internal.policy.impl.PhoneWindow$DecorView' ]:
            #         if DEBUG_COORDS: print >> sys.stderr, "   getXY: skipping %s %s (%d,%d)" % (parent.getClass(), parent.getId(), parent.__getX(), parent.__getY())
            #         parent = parent.parent
            #         continue
            # self.logger.debug("   getXY: parent=%s x=%d hx=%d y=%d hy=%d" % (parent.getId(), x, hx, y, hy))
            hx += parent.__getX()
            hy += parent.__getY()
            parent = parent.parent

        (wvx, wvy) = self.__dumpWindowsInformation(debug=debug)
        self.logger.debug("   getXY: wv=(%d, %d) (windows information)" % (wvx, wvy))
        try:
            if self.windowId and self.windowId in self.windows:
                fw = self.windows[self.windowId]
            else:
                fw = self.windows[self.currentFocus]
            self.logger.debug("    getXY: focused window=%s" % fw)
            self.logger.debug(
                "    getXY: deciding whether to consider statusbar offset"
                " because current focused windows is at (%d, %d) parent (%d, %d)" %
                (fw.wvx, fw.wvy, fw.px, fw.py))
        except KeyError:
            fw = None
        (sbw, sbh) = self.__obtainStatusBarDimensionsIfVisible()
        self.logger.debug("   getXY: sb=(%d, %d) (statusbar dimensions)" % (sbw, sbh))
        statusBarOffset = 0
        pwx = 0
        pwy = 0

        if fw:
            self.logger.debug("    getXY: focused window=%s sb=(%d, %d)" % (fw, sbw, sbh))
            if fw.wvy <= sbh:  # it's very unlikely that fw.wvy < sbh, that is a window over the statusbar
                self.logger.debug("        getXY: yes, considering offset=%d" % sbh)
                statusBarOffset = sbh
            else:
                self.logger.debug("        getXY: no, ignoring statusbar offset fw.wvy=%d>%d" % (fw.wvy, sbh))

            if fw.py == fw.wvy:
                self.logger.debug("        getXY: but wait, fw.py == fw.wvy"
                                  " so we are adjusting by (%d, %d)" % (fw.px, fw.py))
                pwx = fw.px
                pwy = fw.py
            else:
                self.logger.debug("    getXY: fw.py=%d <= fw.wvy=%d, no adjustment" % (fw.py, fw.wvy))

        self.logger.debug(
            "   getXY: returning (%d, %d) ***\n" % (x + hx + wvx + pwx, y + hy + wvy - statusBarOffset + pwy) +
            "                     x=%d+%d+%d+%d\n" % (x, hx, wvx, pwx) +
            "                     y=%d+%d+%d-%d+%d\n" % (y, hy, wvy, statusBarOffset, pwy))
        return x + hx + wvx + pwx, y + hy + wvy - statusBarOffset + pwy

    def __obtainStatusBarDimensionsIfVisible(self):
        sbw = 0
        sbh = 0
        for winId in self.windows:
            w = self.windows[winId]
            self.logger.debug("      __obtainStatusBarDimensionsIfVisible: w=%s   w.activity=%s" % (w, w.activity))
            if w.activity == 'StatusBar':
                if w.wvy == 0 and w.visibility == 0:
                    self.logger.debug("      __obtainStatusBarDimensionsIfVisible: statusBar=(%d, %d)" % (w.wvw, w.wvh))
                    sbw = w.wvw
                    sbh = w.wvh
                break

        return (sbw, sbh)

    def __dumpWindowsInformation(self, debug=False):
        self.windows = {}
        self.currentFocus = None
        dww = self.adb.shell('dumpsys window windows')
        lines = dww.splitlines()
        widRE = re.compile('^ *Window #%s Window\{%s (u\d+ )?%s?.*}:' %
                           (_nd('num'), _nh('winId'), _ns('activity', greedy=True)))
        currentFocusRE = re.compile('^  mCurrentFocus=Window\{%s .*' % _nh('winId'))
        viewVisibilityRE = re.compile(' mViewVisibility=0x%s ' % _nh('visibility'))
        # This is for 4.0.4 API-15
        containingFrameRE = re.compile('^   *mContainingFrame=\[%s,%s\]\[%s,%s\] mParentFrame=\[%s,%s\]\[%s,%s\]' %
                                       (_nd('cx'), _nd('cy'), _nd('cw'), _nd('ch'), _nd('px'), _nd('py'), _nd('pw'),
                                        _nd('ph')))
        contentFrameRE = re.compile('^   *mContentFrame=\[%s,%s\]\[%s,%s\] mVisibleFrame=\[%s,%s\]\[%s,%s\]' %
                                    (_nd('x'), _nd('y'), _nd('w'), _nd('h'), _nd('vx'), _nd('vy'), _nd('vx1'),
                                     _nd('vy1')))
        # This is for 4.1 API-16
        framesRE = re.compile('^   *Frames: containing=\[%s,%s\]\[%s,%s\] parent=\[%s,%s\]\[%s,%s\]' %
                              (_nd('cx'), _nd('cy'), _nd('cw'), _nd('ch'), _nd('px'), _nd('py'), _nd('pw'), _nd('ph')))
        contentRE = re.compile('^     *content=\[%s,%s\]\[%s,%s\] visible=\[%s,%s\]\[%s,%s\]' %
                               (_nd('x'), _nd('y'), _nd('w'), _nd('h'), _nd('vx'), _nd('vy'), _nd('vx1'), _nd('vy1')))
        policyVisibilityRE = re.compile('mPolicyVisibility=%s ' % _ns('policyVisibility', greedy=True))

        for l in range(len(lines)):
            m = widRE.search(lines[l])
            if m:
                num = int(m.group('num'))
                winId = m.group('winId')
                activity = m.group('activity')
                wvx = 0
                wvy = 0
                wvw = 0
                wvh = 0
                px = 0
                py = 0
                visibility = -1
                policyVisibility = 0x0

                for l2 in range(l + 1, len(lines)):
                    m = widRE.search(lines[l2])
                    if m:
                        l += (l2 - 1)
                        break
                    m = viewVisibilityRE.search(lines[l2])
                    if m:
                        visibility = int(m.group('visibility'))
                        self.logger.debug("__dumpWindowsInformation: visibility=%d" % visibility)
                    if self.version >= 17:
                        m = framesRE.search(lines[l2])
                        if m:
                            px, py = obtainPxPy(m)
                            m = contentRE.search(lines[l2 + 2])
                            if m:
                                wvx, wvy = obtainVxVy(m)
                                wvw, wvh = obtainVwVh(m)
                    elif self.version >= 16:
                        m = framesRE.search(lines[l2])
                        if m:
                            px, py = obtainPxPy(m)
                            m = contentRE.search(lines[l2 + 1])
                            if m:
                                # FIXME: the information provided by 'dumpsys window windows' in 4.2.1 (API 16)
                                # when there's a system dialog may not be correct and causes the View coordinates
                                # be offset by this amount, see
                                # https://github.com/dtmilano/AndroidViewClient/issues/29
                                wvx, wvy = obtainVxVy(m)
                                wvw, wvh = obtainVwVh(m)
                    elif self.version == 15:
                        m = containingFrameRE.search(lines[l2])
                        if m:
                            px, py = obtainPxPy(m)
                            m = contentFrameRE.search(lines[l2 + 1])
                            if m:
                                wvx, wvy = obtainVxVy(m)
                                wvw, wvh = obtainVwVh(m)
                    elif self.version == 10:
                        m = containingFrameRE.search(lines[l2])
                        if m:
                            px, py = obtainPxPy(m)
                            m = contentFrameRE.search(lines[l2 + 1])
                            if m:
                                wvx, wvy = obtainVxVy(m)
                                wvw, wvh = obtainVwVh(m)
                    else:
                        self.logger.warning("Unsupported Android version %d" % self.version)

                    # print >> sys.stderr, "Searching policyVisibility in", lines[l2]
                    m = policyVisibilityRE.search(lines[l2])
                    if m:
                        policyVisibility = 0x0 if m.group('policyVisibility') == 'true' else 0x8

                self.windows[winId] = Window(num, winId, activity, wvx, wvy, wvw, wvh, px, py,
                                             visibility + policyVisibility)
            else:
                m = currentFocusRE.search(lines[l])
                if m:
                    self.currentFocus = m.group('winId')

        if self.windowId and self.windowId in self.windows and self.windows[self.windowId].visibility == 0:
            w = self.windows[self.windowId]
            return w.wvx, w.wvy
        elif self.currentFocus in self.windows and self.windows[self.currentFocus].visibility == 0:
            self.logger.debug("__dumpWindowsInformation: focus=%s\n" % self.currentFocus +
                              "__dumpWindowsInformation: %s" % self.windows[self.currentFocus])
            w = self.windows[self.currentFocus]
            return w.wvx, w.wvy
        else:
            self.logger.debug("__dumpWindowsInformation: (0,0)")
            return 0, 0

    def getCoords(self):
        """
        Gets the coords of the View
        @return: A tuple containing the View's coordinates ((L, T), (R, B))
        """
        (x, y) = self.getXY()
        w = self.getWidth()
        h = self.getHeight()
        return (x, y), (x + w, y + h)

    def getPositionAndSize(self):
        """
        Gets the position and size (X,Y, W, H)
        @return: A tuple containing the View's coordinates (X, Y, W, H)
        """
        (x, y) = self.getXY()
        w = self.getWidth()
        h = self.getHeight()
        return x, y, w, h

    def getBounds(self):
        """
        Gets the View bounds
        """
        if 'bounds' in self.attributes:
            return self.attributes['bounds']
        else:
            return self.getCoords()

    def getCenter(self):
        """
        Gets the center coords of the View
        @author: U{Dean Morin <https://github.com/deanmorin>}
        """
        (left, top), (right, bottom) = self.getCoords()
        x = left + (right - left) / 2
        y = top + (bottom - top) / 2
        return x, y

    def touch(self, eventType=ADB.DOWN_AND_UP, deltaX=0, deltaY=0):
        """
        Touches the center of this C{View}. The touch can be displaced from the center by
        using C{deltaX} and C{deltaY} values.
        @param eventType: The event type
        @type eventType: L{adbclient.DOWN}, L{adbclient.UP} or L{adbclient.DOWN_AND_UP}
        @param deltaX: Displacement from center (X axis)
        @type deltaX: int
        @param deltaY: Displacement from center (Y axis)
        @type deltaY: int
        """
        (x, y) = self.getCenter()
        if deltaX:
            x += deltaX
        if deltaY:
            y += deltaY
        if VIEW_CLIENT_TOUCH_WORKAROUND_ENABLED and eventType == self.adb.DOWN_AND_UP:
            self.adb.touch(x, y, eventType=ADB.DOWN)
            time.sleep(50 / 1000.0)
            self.adb.touch(x + 10, y + 10, eventType=ADB.UP)
        else:
            self.adb.touch(x, y, eventType=eventType)

    def escapeSelectorChars(self, selector):
        return selector.replace('@', '\\@').replace(',', '\\,')

    def obtainSelectorForView(self):
        selector = ''
        if self.getContentDescription():
            selector += 'desc@' + self.escapeSelectorChars(self.getContentDescription())
        if self.getText():
            if selector:
                selector += ','
            selector += 'text@' + self.escapeSelectorChars(self.getText())
        if self.getId():
            if selector:
                selector += ','
            selector += 'res@' + self.escapeSelectorChars(self.getId())
        return selector

    def longTouch(self, duration=2000):
        """
        Long touches this C{View}
        @param duration: duration in ms
        """
        (x, y) = self.getCenter()
        self.adb.long_touch(x, y, duration)

    def allPossibleNamesWithColon(self, name):
        l = []
        for _ in range(name.count("_")):
            name = name.replace("_", ":", 1)
            l.append(name)
        return l

    def intersection(self, l1, l2):
        return list(set(l1) & set(l2))

    def containsPoint(self, (x, y)):
        (X, Y, W, H) = self.getPositionAndSize()
        return (x >= X) and (x <= (X + W)) and ((y >= Y) and (y <= (Y + H)))

    def add(self, child):
        """
        Adds a child
        @type child: View
        @param child: The child to add
        """
        child.parent = self
        self.children.append(child)

    def isClickable(self):
        return self.__getattr__('isClickable')()

    def type(self, text, alreadyTouched=False):
        if not text:
            return
        if not alreadyTouched:
            self.touch()
        time.sleep(0.5)
        self.adb.type(text)
        time.sleep(0.5)

    def setText(self, text):
        """
        This function makes sure that any previously entered text is deleted before
        setting the value of the field.
        """
        if self.text() == text:
            return
        self.touch()
        guardrail = 0
        maxSize = len(self.text()) + 1
        while maxSize > guardrail:
            guardrail += 1
            self.adb.press('KEYCODE_DEL', self.adb.DOWN_AND_UP)
            self.adb.press('KEYCODE_FORWARD_DEL', self.adb.DOWN_AND_UP)
        self.type(text, alreadyTouched=True)

    def backspace(self):
        self.touch()
        time.sleep(1)
        self.adb.press('KEYCODE_DEL', self.adb.DOWN_AND_UP)

    def isFocused(self):
        """
        Gets the focused value
        @return: the focused value. If the property cannot be found returns C{False}
        """

        try:
            return True if self.attributes[self.isFocusedProperty].lower() == 'true' else False
        except Exception:
            return False

    def isEnabled(self):
        """
        Gets the enabled value
        @return: the enabled value. If the property cannot be found returns C{False}
        """

        try:
            return True if self.attributes[self.isEnabledProperty].lower() == 'true' else False
        except Exception:
            return False

    def variableNameFromId(self):
        var = None
        _id = self.getId()
        if _id:
            var = _id.replace('.', '_').replace(':', '___').replace('/', '_')
        else:
            _id = self.getUniqueId()
            m = ID_RE.match(_id)
            if m:
                var = m.group(1)
                if m.group(3):
                    var += m.group(3)
                if re.match('^\d', var):
                    var = 'id_' + var
        return var

    def setTarget(self, target):
        self.target = target

    def isTarget(self):
        return self.target

    def __smallStr__(self):
        __str = unicode("View[", 'utf-8', 'replace')
        if "class" in self.attributes:
            __str += " class=" + self.attributes['class']
        __str += " id=%s" % self.getId()
        __str += " ]   parent="
        if self.parent and "class" in self.parent.map:
            __str += "%s" % self.parent.map["class"]
        else:
            __str += "None"

        return __str

    def __tinyStr__(self):
        __str = unicode("View[", 'utf-8', 'replace')
        if "class" in self.attributes:
            __str += " class=" + re.sub('.*\.', '', self.attributes['class'])
        __str += " id=%s" % self.getId()
        __str += " ]"

        return __str

    def __microStr__(self):
        __str = unicode('', 'utf-8', 'replace')
        if "class" in self.attributes:
            __str += re.sub('.*\.', '', self.attributes['class'])
        _id = self.getId().replace('id/no_id/', '-')
        __str += _id
        ((L, T), (R, B)) = self.getCoords()
        __str += '@%04d%04d%04d%04d' % (L, T, R, B)
        __str += ''

        return __str

    def __str__(self):
        __str = unicode("View[", 'utf-8', 'replace')
        if "class" in self.attributes:
            __str += " class=" + self.attributes["class"].__str__() + " "
        for a in self.attributes:
            __str += a + "="
            # decode() works only on python's 8-bit strings
            if isinstance(self.attributes[a], unicode):
                __str += self.attributes[a]
            else:
                __str += unicode(str(self.attributes[a]), 'utf-8', errors='replace')
            __str += " "
        __str += "]   parent="
        if self.parent:
            if "class" in self.parent.map:
                __str += "%s" % self.parent.map["class"]
            else:
                __str += self.parent.getId().__str__()
        else:
            __str += "None"

        return __str


class UiAutomator2AndroidViewClient:
    """
    UiAutomator XML to AndroidViewClient
    """

    def __init__(self, device):
        """
        convert UiAutomator result to ViewClient result
        @param device: the device where the views are dumped from
        @type device: Device
        @return:
        """
        self.device = device
        self.root = None
        self.nodeStack = []
        self.parent = None
        self.views = []
        self.idCount = 1

    def StartElement(self, name, attributes):
        """
        Expat start element event handler
        """
        if name == 'hierarchy':
            pass
        elif name == 'node':
            # Instantiate an Element object
            attributes['uniqueId'] = 'id/no_id/%d' % self.idCount
            bounds = re.split('[\][,]', attributes['bounds'])
            attributes['bounds'] = ((int(bounds[1]), int(bounds[2])), (int(bounds[4]), int(bounds[5])))
            self.idCount += 1
            child = View(attributes=attributes, device=self.device, useUiAutomator=True)
            self.views.append(child)
            # Push element onto the stack and make it a child of parent
            if not self.nodeStack:
                self.root = child
            else:
                self.parent = self.nodeStack[-1]
                self.parent.add(child)
            self.nodeStack.append(child)

    def EndElement(self, name):
        """
        Expat end element event handler
        """

        if name == 'hierarchy':
            pass
        elif name == 'node':
            self.nodeStack.pop()

    def CharacterData(self, data):
        """
        Expat character data event handler
        """
        if data.strip():
            data = data.encode()
            element = self.nodeStack[-1]
            element.cdata += data

    def Parse(self, uiautomatorxml):
        # Create an Expat parser
        parser = xml.parsers.expat.ParserCreate()  # @UndefinedVariable
        # Set the Expat event handlers to our methods
        parser.StartElementHandler = self.StartElement
        parser.EndElementHandler = self.EndElement
        parser.CharacterDataHandler = self.CharacterData
        # Parse the XML File
        try:
            encoded = uiautomatorxml.encode(encoding='utf-8', errors='replace')
            _ = parser.Parse(encoded, True)
        except xml.parsers.expat.ExpatError, ex:  # @UndefinedVariable
            print >> sys.stderr, "ERROR: Offending XML:\n", repr(uiautomatorxml)
            raise RuntimeError(ex)
        return self.root


class UiCollection():
    """
    Used to enumerate a container's user interface (UI) elements for the purpose of counting, or
    targeting a sub elements by a child's text or description.
    """

    pass


class UiScrollable(UiCollection):
    """
    A L{UiCollection} that supports searching for items in scrollable layout elements.
    This class can be used with horizontally or vertically scrollable controls.
    """

    def __init__(self, view):
        self.vc = None
        self.view = view
        self.adb = view.adb
        self.vertical = True
        self.bounds = view.getBounds()
        (self.x, self.y, self.w, self.h) = view.getPositionAndSize()
        self.steps = 10
        self.duration = 500
        self.swipeDeadZonePercentage = 0.1
        self.maxSearchSwipes = 10

    def flingBackward(self):
        if self.vertical:
            s = (self.x + self.w / 2, self.y + self.h * self.swipeDeadZonePercentage)
            e = (self.x + self.w / 2, self.y + self.h - self.h * self.swipeDeadZonePercentage)
        else:
            s = (self.x + self.w * self.swipeDeadZonePercentage, self.y + self.h / 2)
            e = (self.x + self.w * (1.0 - self.swipeDeadZonePercentage), self.y + self.h / 2)
        self.adb.drag(s, e, self.duration, self.steps, self.adb.get_orientation())

    def flingForward(self):
        if self.vertical:
            s = (self.x + self.w / 2, (self.y + self.h) - self.h * self.swipeDeadZonePercentage)
            e = (self.x + self.w / 2, self.y + self.h * self.swipeDeadZonePercentage)
        else:
            s = (self.x + self.w * (1.0 - self.swipeDeadZonePercentage), self.y + self.h / 2)
            e = (self.x + self.w * self.swipeDeadZonePercentage, self.y + self.h / 2)
        self.adb.drag(s, e, self.duration, self.steps, self.adb.get_orientation())

    def flingToBeginning(self, maxSwipes=10):
        if self.vertical:
            for _ in range(maxSwipes):
                self.flingBackward()

    def flingToEnd(self, maxSwipes=10):
        if self.vertical:
            for _ in range(maxSwipes):
                self.flingForward()

    def scrollTextIntoView(self, text):
        """
        Performs a forward scroll action on the scrollable layout element until the text you provided is visible,
        or until swipe attempts have been exhausted. See setMaxSearchSwipes(int)
        """

        if self.vc is None:
            raise ValueError('vc must be set in order to use this method')
        for n in range(self.maxSearchSwipes):
            # FIXME: now I need to figure out the best way of navigating to the ViewClient asossiated
            # with this UiScrollable.
            # It's using setViewClient() now.
            # v = self.vc.findViewWithText(text, root=self.view)
            v = self.vc.findViewWithText(text)
            if v is not None:
                return v
            self.flingForward()
            # self.vc.sleep(1)
            self.vc.dump(-1)
            # WARNING: after this dump, the value kept in self.view is outdated, it should be refreshed
            # in some way
        return None

    def setAsHorizontalList(self):
        self.vertical = False

    def setAsVerticalList(self):
        self.vertical = True

    def setMaxSearchSwipes(self, maxSwipes):
        self.maxSearchSwipes = maxSwipes

    def setViewClient(self, vc):
        self.vc = vc


class ViewClient(Adapter):
    def __init__(self, device, forceviewserveruse=False,
                 localport=VIEW_SERVER_PORT, remoteport=VIEW_SERVER_PORT,
                 ignoreuiautomatorkilled=False, compresseddump=True):
        """
        Constructor

        @type device: Device
        @param device: The device running the C{View server} to which this client will connect
        @type forceviewserveruse: boolean
        @param forceviewserveruse: Force the use of C{ViewServer} even if the conditions to use
                            C{UiAutomator} are satisfied
        @type localport: int
        @param localport: the local port used in the redirection
        @type remoteport: int
        @param remoteport: the remote port used to start the C{ViewServer} in the device or
                           emulator
        @type startviewserver: boolean
        @param startviewserver: Whether to start the B{global} ViewServer
        @type compresseddump: boolean
        @param compresseddump: turns --compressed flag for uiautomator dump on/off
        @:type useuiautomatorhelper: boolean
        @:param useuiautomatorhelper: use UiAutomatorHelper Android app as backend
        """
        self.logger = logging.getLogger("ViewClient")
        if not device:
            raise Exception('Device is not connected')
        self.device = device
        self.adb = device.adb

        self.root = None
        """ The root node """
        self.viewsById = {}
        """ The map containing all the L{View}s indexed by their L{View.getUniqueId()} """
        self.display = {}
        # """ The map containing the device's display properties: width, height and density """
        #
        for prop in ['width', 'height', 'density', 'orientation']:
            self.display[prop] = self.device.get_display_info()[prop]

        self.forceViewServerUse = forceviewserveruse
        """ Force the use of ViewServer even if the conditions to use UiAutomator are satisfied """

        self.useUiAutomator = (self.device.get_sdk_version() >= 16) and not forceviewserveruse
        """ If UIAutomator is supported by the device it will be used """

        self.logger.debug("ViewClient.__init__: useUiAutomator=%s;sdk=%s;forceviewserveruse=%s." %
                          (self.useUiAutomator, self.device.get_sdk_version(), forceviewserveruse))
        self.ignoreUiAutomatorKilled = ignoreuiautomatorkilled
        """ On some devices (i.e. Nexus 7 running 4.2.2) uiautomator is killed just after generating
        the dump file. In many cases the file is already complete so we can ask to ignore the 'Killed'
        message by setting L{ignoreuiautomatorkilled} to C{True}.

        Changes in v2.3.21 that uses C{/dev/tty} instead of a file may have turned this variable
        unnecessary, however it has been kept for backward compatibility.
        """
        self.localPort = localport
        self.remotePort = remoteport
        self.windows = None
        """ The list of windows as obtained by L{ViewClient.list()} """

        # The output of compressed dump is different than output of uncompressed one.
        # If one requires uncompressed output, this option should be set to False
        self.compressedDump = compresseddump
        if self.useUiAutomator:
            self.textProperty = TEXT_PROPERTY_UI_AUTOMATOR
        else:
            self.useViewServer()

    def connect(self):
        if not self.useUiAutomator:
            self.useViewServer()

    def disconnect(self):
        if not self.useUiAutomator:
            try:
                import subprocess
                forward_remove_cmd = "adb -s %s forward --remove tcp:%d" % (self.device.serial, self.localPort)
                subprocess.check_call(forward_remove_cmd.split())
            except Exception as e:
                print e.message

    def useViewServer(self):
        self.useUiAutomator = False
        if self.device.get_sdk_version() <= 10:
            self.textProperty = TEXT_PROPERTY_API_10
        else:
            self.textProperty = TEXT_PROPERTY
        if not self.validServerResponse(self.adb.shell('service call window 3')) \
                and not self.validServerResponse(self.adb.shell('service call window 1 i32 %d' % self.remotePort)):
            msg = 'Cannot start View server.\n' \
                  'This only works on emulator and devices running developer versions.\n' \
                  'Does hierarchyviewer work on your device?\n' \
                  'See https://github.com/dtmilano/AndroidViewClient/wiki/Secure-mode\n\n' \
                  'Device properties:\n' \
                  '    ro.secure=%s\n' \
                  '    ro.debuggable=%s\n' \
                  % (self.device.get_ro_secure(), self.device.get_ro_debuggable())
            raise Exception(msg)

        self.adb.run_cmd(['forward', 'tcp:%d' % self.localPort, 'tcp:%d' % self.remotePort])

    def validServerResponse(self, response):
        """
        Checks the response received from the I{ViewServer}.

        @return: C{True} if the response received matches L{PARCEL_TRUE}, C{False} otherwise
        """
        PARCEL_TRUE = "Result: Parcel(00000000 00000001   '........')"
        ''' The TRUE response parcel '''
        return response.strip() == PARCEL_TRUE

    def dump(self, window=-1, sleep=1):
        """
        Dumps the window content.

        Sleep is useful to wait some time before obtaining the new content when something in the
        window has changed.

        @type window: int or str
        @param window: the window id or name of the window to dump.
                    The B{name} is the package name or the window name (i.e. StatusBar) for
                    system windows.
                    The window id can be provided as C{int} or C{str}. The C{str} should represent
                    and C{int} in either base 10 or 16.
                    Use -1 to dump all windows.
                    This parameter only is used when the backend is B{ViewServer} and it's
                    ignored for B{UiAutomator}.
        @type sleep: int
        @param sleep: sleep in seconds before proceeding to dump the content

        @return: the list of Views as C{str} received from the server after being split into lines
        """

        if sleep > 0:
            time.sleep(sleep)

        if self.useUiAutomator:
            api = self.device.get_sdk_version()
            if api >= 23:
                # In API 23 the process' stdout,in and err are connected to the socket not to the pts as in
                # previous versions, so we can't redirect to /dev/tty
                received = self.adb.shell(
                    'uiautomator dump %s /sdcard/window_dump.xml >/dev/null && cat /sdcard/window_dump.xml' % (
                        '--compressed' if self.compressedDump else ''))
            else:
                # NOTICE:
                # Using /dev/tty this works even on devices with no sdcard
                received = self.adb.shell('uiautomator dump %s /dev/tty >/dev/null' % (
                    '--compressed' if api >= 18 and self.compressedDump else ''))
            if received:
                received = unicode(received, encoding='utf-8', errors='replace')
            else:
                raise RuntimeError('ERROR: Empty UiAutomator dump was received')

            # API19 seems to send this warning as part of the XML.
            # Let's remove it if present
            received = received.replace(
                'WARNING: linker: libdvm.so has text relocations. This is wasting memory and is a security risk. Please fix.\r\n',
                '')
            if re.search('\[: not found', received):
                self.logger.warning("""ERROR: Some emulator images (i.e. android 4.1.2 API 16 generic_x86) does not include the '[' command.
While UiAutomator back-end might be supported 'uiautomator' command fails.
You should force ViewServer back-end.""")
                self.logger.debug("switching to viewserver")
                self.useViewServer()
                return self.dump(window=window, sleep=sleep)

            if received.startswith('ERROR: could not get idle state.'):
                # See https://android.googlesource.com/platform/frameworks/testing/+/jb-mr2-release/uiautomator/cmds/uiautomator/src/com/android/commands/uiautomator/DumpCommand.java
                raise RuntimeError("""The views are being refreshed too frequently to dump.""")
            self.setViewsFromUiAutomatorDump(received)
        else:
            if isinstance(window, str) or isinstance(window, unicode):
                if window != '-1':
                    self.list(sleep=0)
                    found = False
                    for wId in self.windows:
                        try:
                            if window == self.windows[wId]:
                                window = wId
                                found = True
                                break
                        except:
                            pass
                        try:
                            if int(window) == wId:
                                window = wId
                                found = True
                                break
                        except:
                            pass
                        try:
                            if int(window, 16) == wId:
                                window = wId
                                found = True
                                break
                        except:
                            pass

                    if not found:
                        raise RuntimeError("ERROR: Cannot find window '%s' in %s" % (window, self.windows))
                else:
                    window = -1

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((VIEW_SERVER_HOST, self.localPort))
            except socket.error, ex:
                raise RuntimeError("ERROR: Connecting to %s:%d: %s" % (VIEW_SERVER_HOST, self.localPort, ex))
            cmd = 'dump %x\r\n' % window
            s.send(cmd)
            received = ""
            doneRE = re.compile("DONE")
            ViewClient.setAlarm(120)
            while True:
                received += s.recv(1024)
                if doneRE.search(received[-7:]):
                    break
            s.close()
            ViewClient.setAlarm(0)
            if received:
                for c in received:
                    if ord(c) > 127:
                        received = unicode(received, encoding='utf-8', errors='replace')
                        break
            if window == -1:
                self.setViews(received)
            else:
                self.setViews(received, hex(window)[2:])

        return self.views

    @staticmethod
    def setAlarm(timeout):
        import platform, signal
        osName = platform.system()
        if osName.startswith('Windows'):  # alarm is not implemented in Windows
            return
        signal.alarm(timeout)

    def list(self, sleep=1):
        """
        List the windows.

        Sleep is useful to wait some time before obtaining the new content when something in the
        window has changed.
        This also sets L{self.windows} as the list of windows.

        @type sleep: int
        @param sleep: sleep in seconds before proceeding to dump the content

        @return: the list of windows
        """

        if sleep > 0:
            time.sleep(sleep)

        if self.useUiAutomator:
            raise Exception("Not implemented yet: listing windows with UiAutomator")
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((VIEW_SERVER_HOST, self.localPort))
            except socket.error, ex:
                raise RuntimeError("ERROR: Connecting to %s:%d: %s" % (VIEW_SERVER_HOST, self.localPort, ex))
            s.send('list\r\n')
            received = ""
            doneRE = re.compile("DONE")
            while True:
                received += s.recv(1024)
                if doneRE.search(received[-7:]):
                    break
            s.close()

            self.windows = {}
            for line in received.split('\n'):
                if not line:
                    break
                if doneRE.search(line):
                    break
                values = line.split()
                if len(values) > 1:
                    package = values[1]
                else:
                    package = "UNKNOWN"
                if len(values) > 0:
                    wid = values[0]
                else:
                    wid = '00000000'
                self.windows[int('0x' + wid, 16)] = package
            return self.windows

    def setViews(self, received, windowId=None):
        """
        Sets L{self.views} to the received value splitting it into lines.

        @type received: str
        @param received: the string received from the I{View Serverw}
        """

        if not received or received == "":
            raise ValueError("received is empty")
        if not isinstance(received, str) and not isinstance(received, unicode):
            raise ValueError("received is %s instead of str: %s" % (type(received), received))
        self.views = []
        """ The list of Views represented as C{str} obtained after splitting it into lines after being received from the server. Done by L{self.setViews()}. """
        self.__parseTree(received.split("\n"), windowId)

    def __parseTree(self, receivedLines, windowId=None):
        """
        Parses the View tree contained in L{receivedLines}. The tree is created and the root node assigned to L{self.root}.
        This method also assigns L{self.viewsById} values using L{View.getUniqueId} as the key.

        @type receivedLines: list
        @param receivedLines: the string received from B{View Server}
        """

        self.root = None
        self.viewsById = {}
        self.views = []
        parent = None
        parents = []
        treeLevel = -1
        newLevel = -1
        lastView = None
        for v in receivedLines:
            if v == '' or v == 'DONE' or v == 'DONE.':
                break
            attrs = self.__parseAttrs(v)
            if not self.root:
                if v[0] == ' ':
                    raise Exception("Unexpected root element starting with ' '.")
                self.root = View(attrs, self.device, self.useUiAutomator, windowId)
                treeLevel = 0
                newLevel = 0
                lastView = self.root
                parent = self.root
                parents.append(parent)
            else:
                newLevel = (len(v) - len(v.lstrip()))
                if newLevel == 0:
                    raise Exception("newLevel==0 treeLevel=%d but tree can have only one root, v=%s" % (treeLevel, v))
                child = View(attrs, self.device, self.useUiAutomator, windowId)
                if newLevel == treeLevel:
                    parent.add(child)
                    lastView = child
                elif newLevel > treeLevel:
                    if (newLevel - treeLevel) != 1:
                        raise Exception("newLevel jumps %d levels, v=%s" % ((newLevel - treeLevel), v))
                    parent = lastView
                    parents.append(parent)
                    parent.add(child)
                    lastView = child
                    treeLevel = newLevel
                else:  # newLevel < treeLevel
                    for _ in range(treeLevel - newLevel):
                        parents.pop()
                    parent = parents.pop()
                    parents.append(parent)
                    parent.add(child)
                    treeLevel = newLevel
                    lastView = child
            self.views.append(lastView)
            self.viewsById[lastView.getUniqueId()] = lastView

    def __parseAttrs(self, strArgs):
        """
        Splits the C{View} attributes in C{strArgs} and optionally adds the view id to the C{viewsById} list.

        Unique Ids
        ==========
        It is very common to find C{View}s having B{NO_ID} as the Id. This turns very difficult to
        use L{self.findViewById()}. To help in this situation this method assigns B{unique Ids}.

        The B{unique Ids} are generated using the pattern C{id/no_id/<number>} with C{<number>} starting
        at 1.

        @type strArgs: str
        @param strArgs: the string containing the raw list of attributes and values

        @return: Returns the attributes map.
        """

        if self.useUiAutomator:
            raise RuntimeError("This method is not compatible with UIAutomator")

        strArgs = strArgs.strip()

        idRE = re.compile("(?P<viewId>id/\S+)")
        attrRE = re.compile('%s(?P<parens>\(\))?=%s,(?P<val>[^ ]*)' % (_ns('attr'), _nd('len')), flags=re.DOTALL)
        hashRE = re.compile('%s@%s' % (_ns('class'), _nh('oid')))

        attrs = {}
        viewId = None
        m = idRE.search(strArgs)
        if m:
            viewId = m.group('viewId')

        str_start = 0
        str_len = len(strArgs)

        while True:
            m = attrRE.match(strArgs, str_start)
            if m:
                __attr = m.group('attr')
                __parens = '()' if m.group('parens') else ''
                __len = int(m.group('len'))
                __val_start = m.start('val')
                __val_end = __val_start + __len
                __val = strArgs[__val_start:__val_end]
                attrs[__attr + __parens] = __val
                str_start = __val_end
            else:
                m = hashRE.match(strArgs, str_start)
                if m:
                    attrs['class'] = m.group('class')
                    attrs['oid'] = m.group('oid')
                    str_start = m.end(0)
                else:
                    self.logger.warning("__parseAttrs doesn't match: %s" % strArgs[str_start:])

            if str_start >= str_len or strArgs[str_start:] == " " or strArgs[str_start:] == "DONE":
                break

            if strArgs[str_start] == " ":
                str_start += 1
            else:
                self.logger.warning("__parseAttrs unexpected token: %s" % strArgs[str_start:])
                break

        if True:  # was assignViewById
            if not viewId:
                # If the view has NO_ID we are assigning a default id here (id/no_id) which is
                # immediately incremented if another view with no id was found before to generate
                # a unique id
                viewId = "id/no_id/1"
            if viewId in self.viewsById:
                # sometimes the view ids are not unique, so let's generate a unique id here
                i = 1
                while True:
                    newId = re.sub('/\d+$', '', viewId) + '/%d' % i
                    if newId not in self.viewsById:
                        viewId = newId
                        break
                    i += 1
            # We are assigning a new attribute to keep the original id preserved, which could have
            # been NO_ID repeated multiple times
            attrs['uniqueId'] = viewId

        return attrs

    def setViewsFromUiAutomatorDump(self, received):
        self.views = []
        self.__parseTreeFromUiAutomatorDump(received)

    def __parseTreeFromUiAutomatorDump(self, receivedXml):
        parser = UiAutomator2AndroidViewClient(self.device)
        try:
            start_xml_index = receivedXml.index("<")
            end_xml_index = receivedXml.rindex(">")
        except ValueError:
            raise ValueError("received does not contain valid XML: " + receivedXml)

        self.root = parser.Parse(receivedXml[start_xml_index:end_xml_index + 1])
        self.views = parser.views
        self.viewsById = {}
        for v in self.views:
            self.viewsById[v.getUniqueId()] = v
        self.__updateNavButtons()

    def __updateNavButtons(self):
        """
        Updates the navigation buttons that might be on the device screen.
        """

        navButtons = None
        for v in self.views:
            if v.getId() == 'com.android.systemui:id/nav_buttons':
                navButtons = v
                break
        if navButtons:
            self.navBack = self.findViewById('com.android.systemui:id/back', navButtons)
            self.navHome = self.findViewById('com.android.systemui:id/home', navButtons)
            self.navRecentApps = self.findViewById('com.android.systemui:id/recent_apps', navButtons)
        else:
            self.navBack = None
            self.navHome = None
            self.navRecentApps = None

    def findViewById(self, viewId, root="ROOT", viewFilter=None):
        """
        Finds the View with the specified viewId.
        @type viewId: str
        @param viewId: the ID of the view to find
        @type root: str
        @type root: View
        @param root: the root node of the tree where the View will be searched
        @type: viewFilter: function
        @param viewFilter: a function that will be invoked providing the candidate View as a parameter
                           and depending on the return value (C{True} or C{False}) the View will be
                           selected and returned as the result of C{findViewById()} or ignored.
                           This can be C{None} and no extra filtering is applied.
        @return: the C{View} found or C{None}
        """

        if not root:
            return None

        if type(root) == types.StringType and root == "ROOT":
            return self.findViewById(viewId, self.root, viewFilter)

        if root.getId() == viewId:
            if viewFilter:
                if viewFilter(root):
                    return root
            else:
                return root

        if re.match('^id/no_id', viewId) or re.match('^id/.+/.+', viewId):
            if root.getUniqueId() == viewId:
                if viewFilter:
                    if viewFilter(root):
                        return root
                else:
                    return root

        for ch in root.children:
            foundView = self.findViewById(viewId, ch, viewFilter)
            if foundView:
                if viewFilter:
                    if viewFilter(foundView):
                        return foundView
                else:
                    return foundView
