package org.jboss.netty.logging;

import java.util.logging.Level;
import java.util.logging.Logger;

class JdkLogger extends AbstractInternalLogger {
    private final Logger logger;
    private final String loggerName;

    JdkLogger(Logger logger2, String loggerName2) {
        this.logger = logger2;
        this.loggerName = loggerName2;
    }

    public void debug(String msg) {
        this.logger.logp(Level.FINE, this.loggerName, null, msg);
    }

    public void debug(String msg, Throwable cause) {
        this.logger.logp(Level.FINE, this.loggerName, null, msg, cause);
    }

    public void error(String msg) {
        this.logger.logp(Level.SEVERE, this.loggerName, null, msg);
    }

    public void error(String msg, Throwable cause) {
        this.logger.logp(Level.SEVERE, this.loggerName, null, msg, cause);
    }

    public void info(String msg) {
        this.logger.logp(Level.INFO, this.loggerName, null, msg);
    }

    public void info(String msg, Throwable cause) {
        this.logger.logp(Level.INFO, this.loggerName, null, msg, cause);
    }

    public boolean isDebugEnabled() {
        return this.logger.isLoggable(Level.FINE);
    }

    public boolean isErrorEnabled() {
        return this.logger.isLoggable(Level.SEVERE);
    }

    public boolean isInfoEnabled() {
        return this.logger.isLoggable(Level.INFO);
    }

    public boolean isWarnEnabled() {
        return this.logger.isLoggable(Level.WARNING);
    }

    public void warn(String msg) {
        this.logger.logp(Level.WARNING, this.loggerName, null, msg);
    }

    public void warn(String msg, Throwable cause) {
        this.logger.logp(Level.WARNING, this.loggerName, null, msg, cause);
    }

    public String toString() {
        return this.loggerName;
    }
}