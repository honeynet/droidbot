var c_open = Module.findExportByName("libc.so", "open");
var c_write = Module.findExportByName("libc.so", "write");
var c_mmap = Module.findExportByName("libc.so", "mmap");
var c_madvise = Module.findExportByName("libc.so", "madvise");
var c_pthread_create = Module.findExportByName("libc.so", "pthread_create")
if (c_open) {
    Interceptor.attach(c_open, {
        onEnter : function(args) {
            send("call libc->open");
        },
        onLeave : function(retval) {
        }
    });
}
/*
if (c_write) {
    Interceptor.attach(c_write, {
        onEnter : function(args) {
            send("call libc->write");
        },
        onLeave : function(retval) {
        }
    });
if (c_mmap) {
    Interceptor.attach(c_mmap, {
        onEnter : function(args) {
            send("call libc->mmap");
        },
        onLeave : function(retval) {
        }
    });
}
if (c_madvise) {
    Interceptor.attach(c_madvise, {
        onEnter : function(args) {
            send("call libc->madvise");
        },
        onLeave : function(retval) {
        }
    });
}
if (c_pthread_create) {
    Interceptor.attach(c_pthread_create, {
        onEnter : function(args) {
            send("call libc->pthread_create");
        },
        onLeave : function(retval) {
        }
    });
}
*/