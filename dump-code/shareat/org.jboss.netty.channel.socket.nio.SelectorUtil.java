package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.Selector;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.internal.SystemPropertyUtil;

final class SelectorUtil {
    static final int DEFAULT_IO_THREADS = (Runtime.getRuntime().availableProcessors() * 2);
    static final long DEFAULT_SELECT_TIMEOUT = 500;
    static final boolean EPOLL_BUG_WORKAROUND = SystemPropertyUtil.getBoolean("org.jboss.netty.epollBugWorkaround", false);
    static final long SELECT_TIMEOUT = SystemPropertyUtil.getLong("org.jboss.netty.selectTimeout", 500);
    static final long SELECT_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(SELECT_TIMEOUT);
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(SelectorUtil.class);

    static {
        try {
            if (System.getProperty("sun.nio.ch.bugLevel") == null) {
                System.setProperty("sun.nio.ch.bugLevel", "");
            }
        } catch (SecurityException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Unable to get/set System Property '" + "sun.nio.ch.bugLevel" + '\'', e);
            }
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Using select timeout of " + SELECT_TIMEOUT);
            logger.debug("Epoll-bug workaround enabled = " + EPOLL_BUG_WORKAROUND);
        }
    }

    static Selector open() throws IOException {
        return Selector.open();
    }

    static int select(Selector selector) throws IOException {
        try {
            return selector.select(SELECT_TIMEOUT);
        } catch (CancelledKeyException e) {
            if (logger.isDebugEnabled()) {
                logger.debug(CancelledKeyException.class.getSimpleName() + " raised by a Selector - JDK bug?", e);
            }
            return -1;
        }
    }

    private SelectorUtil() {
    }
}