package org.jboss.netty.logging;

import org.jboss.netty.util.internal.StackTraceSimplifier;

public abstract class InternalLoggerFactory {
    private static volatile InternalLoggerFactory defaultFactory = new JdkLoggerFactory();

    public abstract InternalLogger newInstance(String str);

    static {
        StackTraceSimplifier.simplify(new Exception());
    }

    public static InternalLoggerFactory getDefaultFactory() {
        return defaultFactory;
    }

    public static void setDefaultFactory(InternalLoggerFactory defaultFactory2) {
        if (defaultFactory2 == null) {
            throw new NullPointerException("defaultFactory");
        }
        defaultFactory = defaultFactory2;
    }

    public static InternalLogger getInstance(Class<?> clazz) {
        return getInstance(clazz.getName());
    }

    public static InternalLogger getInstance(String name) {
        final InternalLogger logger = getDefaultFactory().newInstance(name);
        return new InternalLogger() {
            public void debug(String msg) {
                logger.debug(msg);
            }

            public void debug(String msg, Throwable cause) {
                StackTraceSimplifier.simplify(cause);
                logger.debug(msg, cause);
            }

            public void error(String msg) {
                logger.error(msg);
            }

            public void error(String msg, Throwable cause) {
                StackTraceSimplifier.simplify(cause);
                logger.error(msg, cause);
            }

            public void info(String msg) {
                logger.info(msg);
            }

            public void info(String msg, Throwable cause) {
                StackTraceSimplifier.simplify(cause);
                logger.info(msg, cause);
            }

            public boolean isDebugEnabled() {
                return logger.isDebugEnabled();
            }

            public boolean isErrorEnabled() {
                return logger.isErrorEnabled();
            }

            public boolean isInfoEnabled() {
                return logger.isInfoEnabled();
            }

            public boolean isWarnEnabled() {
                return logger.isWarnEnabled();
            }

            public void warn(String msg) {
                logger.warn(msg);
            }

            public void warn(String msg, Throwable cause) {
                StackTraceSimplifier.simplify(cause);
                logger.warn(msg, cause);
            }

            public boolean isEnabled(InternalLogLevel level) {
                return logger.isEnabled(level);
            }

            public void log(InternalLogLevel level, String msg) {
                logger.log(level, msg);
            }

            public void log(InternalLogLevel level, String msg, Throwable cause) {
                StackTraceSimplifier.simplify(cause);
                logger.log(level, msg, cause);
            }
        };
    }
}