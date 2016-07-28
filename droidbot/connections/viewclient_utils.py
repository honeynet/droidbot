# Copyright (C) 2012-2015  Diego Torres Milano
# These are util classes/methods used in androidviewclient
# In droidbot, some methods in adb.py and view_client.py are using these util methods


def _nd(name):
    """
    @return: Returns a named decimal regex
    """
    return '(?P<%s>\d+)' % name


def _nh(name):
    """
    @return: Returns a named hex regex
    """
    return '(?P<%s>[0-9a-f]+)' % name


def _ns(name, greedy=False):
    """
    NOTICE: this is using a non-greedy (or minimal) regex
    @type name: str
    @param name: the name used to tag the expression
    @type greedy: bool
    @param greedy: Whether the regex is greedy or not
    @return: Returns a named string regex (only non-whitespace characters allowed)
    """
    return '(?P<%s>\S+%s)' % (name, '' if greedy else '?')


def obtainPxPy(m):
    px = int(m.group('px'))
    py = int(m.group('py'))
    return (px, py)


def obtainVxVy(m):
    wvx = int(m.group('vx'))
    wvy = int(m.group('vy'))
    return wvx, wvy


def obtainVwVh(m):
    (wvx, wvy) = obtainVxVy(m)
    wvx1 = int(m.group('vx1'))
    wvy1 = int(m.group('vy1'))
    return (wvx1 - wvx, wvy1 - wvy)


class Window(object):
    """
    Window class
    """

    def __init__(self, num, winId, activity, wvx, wvy, wvw, wvh, px, py, visibility, focused=False):
        """
        Constructor
        @type num: int
        @param num: Ordering number in Window Manager
        @type winId: str
        @param winId: the window ID
        @type activity: str
        @param activity: the activity (or sometimes other component) owning the window
        @type wvx: int
        @param wvx: window's virtual X
        @type wvy: int
        @param wvy: window's virtual Y
        @type wvw: int
        @param wvw: window's virtual width
        @type wvh: int
        @param wvh: window's virtual height
        @type px: int
        @param px: parent's X
        @type py: int
        @param py: parent's Y
        @type visibility: int
        @param visibility: visibility of the window
        """

        self.num = num
        self.winId = winId
        self.activity = activity
        self.wvx = wvx
        self.wvy = wvy
        self.wvw = wvw
        self.wvh = wvh
        self.px = px
        self.py = py
        self.visibility = visibility
        self.focused = focused

    def __str__(self):
        return "Window(%d, wid=%s, a=%s, x=%d, y=%d, w=%d, h=%d, px=%d, py=%d, v=%d, f=%s)" % \
               (self.num, self.winId, self.activity, self.wvx, self.wvy, self.wvw, self.wvh, self.px, self.py,
                self.visibility, self.focused)
