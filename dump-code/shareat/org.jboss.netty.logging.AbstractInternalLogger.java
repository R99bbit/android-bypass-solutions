package org.jboss.netty.logging;

public abstract class AbstractInternalLogger implements InternalLogger {
    protected AbstractInternalLogger() {
    }

    public boolean isEnabled(InternalLogLevel level) {
        switch (level) {
            case DEBUG:
                return isDebugEnabled();
            case INFO:
                return isInfoEnabled();
            case WARN:
                return isWarnEnabled();
            case ERROR:
                return isErrorEnabled();
            default:
                throw new Error();
        }
    }

    public void log(InternalLogLevel level, String msg, Throwable cause) {
        switch (level) {
            case DEBUG:
                debug(msg, cause);
                return;
            case INFO:
                info(msg, cause);
                return;
            case WARN:
                warn(msg, cause);
                return;
            case ERROR:
                error(msg, cause);
                return;
            default:
                throw new Error();
        }
    }

    public void log(InternalLogLevel level, String msg) {
        switch (level) {
            case DEBUG:
                debug(msg);
                return;
            case INFO:
                info(msg);
                return;
            case WARN:
                warn(msg);
                return;
            case ERROR:
                error(msg);
                return;
            default:
                throw new Error();
        }
    }
}