package org.jboss.netty.logging;

import org.slf4j.Logger;

class Slf4JLogger extends AbstractInternalLogger {
    private final Logger logger;

    Slf4JLogger(Logger logger2) {
        this.logger = logger2;
    }

    public void debug(String msg) {
        this.logger.debug(msg);
    }

    public void debug(String msg, Throwable cause) {
        this.logger.debug(msg, cause);
    }

    public void error(String msg) {
        this.logger.error(msg);
    }

    public void error(String msg, Throwable cause) {
        this.logger.error(msg, cause);
    }

    public void info(String msg) {
        this.logger.info(msg);
    }

    public void info(String msg, Throwable cause) {
        this.logger.info(msg, cause);
    }

    public boolean isDebugEnabled() {
        return this.logger.isDebugEnabled();
    }

    public boolean isErrorEnabled() {
        return this.logger.isErrorEnabled();
    }

    public boolean isInfoEnabled() {
        return this.logger.isInfoEnabled();
    }

    public boolean isWarnEnabled() {
        return this.logger.isWarnEnabled();
    }

    public void warn(String msg) {
        this.logger.warn(msg);
    }

    public void warn(String msg, Throwable cause) {
        this.logger.warn(msg, cause);
    }

    public String toString() {
        return String.valueOf(this.logger.getName());
    }
}