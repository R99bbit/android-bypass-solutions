package org.jboss.netty.logging;

import org.osgi.service.log.LogService;

class OsgiLogger extends AbstractInternalLogger {
    private final InternalLogger fallback;
    private final String name;
    private final OsgiLoggerFactory parent;
    private final String prefix;

    OsgiLogger(OsgiLoggerFactory parent2, String name2, InternalLogger fallback2) {
        this.parent = parent2;
        this.name = name2;
        this.fallback = fallback2;
        this.prefix = '[' + name2 + "] ";
    }

    public void debug(String msg) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(4, this.prefix + msg);
        } else {
            this.fallback.debug(msg);
        }
    }

    public void debug(String msg, Throwable cause) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(4, this.prefix + msg, cause);
        } else {
            this.fallback.debug(msg, cause);
        }
    }

    public void error(String msg) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(1, this.prefix + msg);
        } else {
            this.fallback.error(msg);
        }
    }

    public void error(String msg, Throwable cause) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(1, this.prefix + msg, cause);
        } else {
            this.fallback.error(msg, cause);
        }
    }

    public void info(String msg) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(3, this.prefix + msg);
        } else {
            this.fallback.info(msg);
        }
    }

    public void info(String msg, Throwable cause) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(3, this.prefix + msg, cause);
        } else {
            this.fallback.info(msg, cause);
        }
    }

    public boolean isDebugEnabled() {
        return true;
    }

    public boolean isErrorEnabled() {
        return true;
    }

    public boolean isInfoEnabled() {
        return true;
    }

    public boolean isWarnEnabled() {
        return true;
    }

    public void warn(String msg) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(2, this.prefix + msg);
        } else {
            this.fallback.warn(msg);
        }
    }

    public void warn(String msg, Throwable cause) {
        LogService logService = this.parent.getLogService();
        if (logService != null) {
            logService.log(2, this.prefix + msg, cause);
        } else {
            this.fallback.warn(msg, cause);
        }
    }

    public String toString() {
        return this.name;
    }
}