class Intent(object):
    """
    this class describes a intent event
    """

    def __init__(self, prefix="start", action=None, data_uri=None, mime_type=None, category=None,
                 component=None, flag=None, extra_keys=None, extra_string=None, extra_boolean=None,
                 extra_int=None, extra_long=None, extra_float=None, extra_uri=None, extra_component=None,
                 extra_array_int=None, extra_array_long=None, extra_array_float=None, flags=None, suffix=""):
        self.event_type = 'intent'
        self.prefix = prefix
        self.action = action
        self.data_uri = data_uri
        self.mime_type = mime_type
        self.category = category
        self.component = component
        self.flag = flag
        self.extra_keys = extra_keys
        self.extra_string = extra_string
        self.extra_boolean = extra_boolean
        self.extra_int = extra_int
        self.extra_long = extra_long
        self.extra_float = extra_float
        self.extra_uri = extra_uri
        self.extra_component = extra_component
        self.extra_array_int = extra_array_int
        self.extra_array_long = extra_array_long
        self.extra_array_float = extra_array_float
        self.flags = flags
        self.suffix = suffix
        self.cmd = None
        self.get_cmd()

    def get_cmd(self):
        """
        convert this intent to cmd string
        :rtype : object
        :return: str, cmd string
        """
        if self.cmd is not None:
            return self.cmd
        cmd = "am "
        if self.prefix:
            cmd += self.prefix
        if self.action is not None:
            cmd += " -a " + self.action
        if self.data_uri is not None:
            cmd += " -d " + self.data_uri
        if self.mime_type is not None:
            cmd += " -t " + self.mime_type
        if self.category is not None:
            cmd += " -c " + self.category
        if self.component is not None:
            cmd += " -n " + self.component
        if self.flag is not None:
            cmd += " -f " + self.flag
        if self.extra_keys:
            for key in self.extra_keys:
                cmd += " --esn '%s'" % key
        if self.extra_string:
            for key in list(self.extra_string.keys()):
                cmd += " -e '%s' '%s'" % (key, self.extra_string[key])
        if self.extra_boolean:
            for key in list(self.extra_boolean.keys()):
                cmd += " -ez '%s' %s" % (key, self.extra_boolean[key])
        if self.extra_int:
            for key in list(self.extra_int.keys()):
                cmd += " -ei '%s' %s" % (key, self.extra_int[key])
        if self.extra_long:
            for key in list(self.extra_long.keys()):
                cmd += " -el '%s' %s" % (key, self.extra_long[key])
        if self.extra_float:
            for key in list(self.extra_float.keys()):
                cmd += " -ef '%s' %s" % (key, self.extra_float[key])
        if self.extra_uri:
            for key in list(self.extra_uri.keys()):
                cmd += " -eu '%s' '%s'" % (key, self.extra_uri[key])
        if self.extra_component:
            for key in list(self.extra_component.keys()):
                cmd += " -ecn '%s' %s" % (key, self.extra_component[key])
        if self.extra_array_int:
            for key in list(self.extra_array_int.keys()):
                cmd += " -eia '%s' %s" % (key, ",".join(self.extra_array_int[key]))
        if self.extra_array_long:
            for key in list(self.extra_array_long.keys()):
                cmd += " -ela '%s' %s" % (key, ",".join(self.extra_array_long[key]))
        if self.extra_array_float:
            for key in list(self.extra_array_float.keys()):
                cmd += " -efa '%s' %s" % (key, ",".join(self.extra_array_float[key]))
        if self.flags:
            cmd += " " + " ".join(self.flags)
        if self.suffix:
            cmd += " " + self.suffix
        self.cmd = cmd
        return self.cmd

    def __str__(self):
        return self.get_cmd()
