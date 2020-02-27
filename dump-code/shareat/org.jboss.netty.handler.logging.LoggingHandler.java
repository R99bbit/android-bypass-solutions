package org.jboss.netty.handler.logging;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.logging.InternalLogLevel;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

@Sharable
public class LoggingHandler implements ChannelUpstreamHandler, ChannelDownstreamHandler {
    private static final char[] BYTE2CHAR = new char[256];
    private static final String[] BYTE2HEX = new String[256];
    private static final String[] BYTEPADDING = new String[16];
    private static final InternalLogLevel DEFAULT_LEVEL = InternalLogLevel.DEBUG;
    private static final String[] HEXPADDING = new String[16];
    private static final String NEWLINE = String.format("%n", new Object[0]);
    private final boolean hexDump;
    private final InternalLogLevel level;
    private final InternalLogger logger;

    static {
        int i = 0;
        while (i < 10) {
            StringBuilder buf = new StringBuilder(3);
            buf.append(" 0");
            buf.append(i);
            BYTE2HEX[i] = buf.toString();
            i++;
        }
        while (i < 16) {
            StringBuilder buf2 = new StringBuilder(3);
            buf2.append(" 0");
            buf2.append((char) ((i + 97) - 10));
            BYTE2HEX[i] = buf2.toString();
            i++;
        }
        while (i < BYTE2HEX.length) {
            StringBuilder buf3 = new StringBuilder(3);
            buf3.append(' ');
            buf3.append(Integer.toHexString(i));
            BYTE2HEX[i] = buf3.toString();
            i++;
        }
        for (int i2 = 0; i2 < HEXPADDING.length; i2++) {
            int padding = HEXPADDING.length - i2;
            StringBuilder buf4 = new StringBuilder(padding * 3);
            for (int j = 0; j < padding; j++) {
                buf4.append("   ");
            }
            HEXPADDING[i2] = buf4.toString();
        }
        for (int i3 = 0; i3 < BYTEPADDING.length; i3++) {
            int padding2 = BYTEPADDING.length - i3;
            StringBuilder buf5 = new StringBuilder(padding2);
            for (int j2 = 0; j2 < padding2; j2++) {
                buf5.append(' ');
            }
            BYTEPADDING[i3] = buf5.toString();
        }
        for (int i4 = 0; i4 < BYTE2CHAR.length; i4++) {
            if (i4 <= 31 || i4 >= 127) {
                BYTE2CHAR[i4] = '.';
            } else {
                BYTE2CHAR[i4] = (char) i4;
            }
        }
    }

    public LoggingHandler() {
        this(true);
    }

    public LoggingHandler(InternalLogLevel level2) {
        this(level2, true);
    }

    public LoggingHandler(boolean hexDump2) {
        this(DEFAULT_LEVEL, hexDump2);
    }

    public LoggingHandler(InternalLogLevel level2, boolean hexDump2) {
        if (level2 == null) {
            throw new NullPointerException(Param.LEVEL);
        }
        this.logger = InternalLoggerFactory.getInstance(getClass());
        this.level = level2;
        this.hexDump = hexDump2;
    }

    public LoggingHandler(Class<?> clazz) {
        this(clazz, true);
    }

    public LoggingHandler(Class<?> clazz, boolean hexDump2) {
        this(clazz, DEFAULT_LEVEL, hexDump2);
    }

    public LoggingHandler(Class<?> clazz, InternalLogLevel level2) {
        this(clazz, level2, true);
    }

    public LoggingHandler(Class<?> clazz, InternalLogLevel level2, boolean hexDump2) {
        if (clazz == null) {
            throw new NullPointerException("clazz");
        } else if (level2 == null) {
            throw new NullPointerException(Param.LEVEL);
        } else {
            this.logger = InternalLoggerFactory.getInstance(clazz);
            this.level = level2;
            this.hexDump = hexDump2;
        }
    }

    public LoggingHandler(String name) {
        this(name, true);
    }

    public LoggingHandler(String name, boolean hexDump2) {
        this(name, DEFAULT_LEVEL, hexDump2);
    }

    public LoggingHandler(String name, InternalLogLevel level2, boolean hexDump2) {
        if (name == null) {
            throw new NullPointerException("name");
        } else if (level2 == null) {
            throw new NullPointerException(Param.LEVEL);
        } else {
            this.logger = InternalLoggerFactory.getInstance(name);
            this.level = level2;
            this.hexDump = hexDump2;
        }
    }

    public InternalLogger getLogger() {
        return this.logger;
    }

    public InternalLogLevel getLevel() {
        return this.level;
    }

    public void log(ChannelEvent e) {
        if (getLogger().isEnabled(this.level)) {
            String msg = e.toString();
            if (this.hexDump && (e instanceof MessageEvent)) {
                MessageEvent me = (MessageEvent) e;
                if (me.getMessage() instanceof ChannelBuffer) {
                    msg = msg + formatBuffer((ChannelBuffer) me.getMessage());
                }
            }
            if (e instanceof ExceptionEvent) {
                getLogger().log(this.level, msg, ((ExceptionEvent) e).getCause());
            } else {
                getLogger().log(this.level, msg);
            }
        }
    }

    private static String formatBuffer(ChannelBuffer buf) {
        int length = buf.readableBytes();
        StringBuilder dump = new StringBuilder(((length % 15 == 0 ? 0 : 1) + (length / 16) + 4) * 80);
        dump.append(NEWLINE + "         +-------------------------------------------------+" + NEWLINE + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |" + NEWLINE + "+--------+-------------------------------------------------+----------------+");
        int startIndex = buf.readerIndex();
        int endIndex = buf.writerIndex();
        int i = startIndex;
        while (i < endIndex) {
            int relIdx = i - startIndex;
            int relIdxMod16 = relIdx & 15;
            if (relIdxMod16 == 0) {
                dump.append(NEWLINE);
                dump.append(Long.toHexString((((long) relIdx) & 4294967295L) | 4294967296L));
                dump.setCharAt(dump.length() - 9, '|');
                dump.append('|');
            }
            dump.append(BYTE2HEX[buf.getUnsignedByte(i)]);
            if (relIdxMod16 == 15) {
                dump.append(" |");
                for (int j = i - 15; j <= i; j++) {
                    dump.append(BYTE2CHAR[buf.getUnsignedByte(j)]);
                }
                dump.append('|');
            }
            i++;
        }
        if (((i - startIndex) & 15) != 0) {
            int remainder = length & 15;
            dump.append(HEXPADDING[remainder]);
            dump.append(" |");
            for (int j2 = i - remainder; j2 < i; j2++) {
                dump.append(BYTE2CHAR[buf.getUnsignedByte(j2)]);
            }
            dump.append(BYTEPADDING[remainder]);
            dump.append('|');
        }
        dump.append(NEWLINE + "+--------+-------------------------------------------------+----------------+");
        return dump.toString();
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        log(e);
        ctx.sendUpstream(e);
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        log(e);
        ctx.sendDownstream(e);
    }
}