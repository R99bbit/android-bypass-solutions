package org.jboss.netty.channel.socket.oio;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;
import java.util.regex.Pattern;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DefaultFileRegion;
import org.jboss.netty.channel.FileRegion;

class OioWorker extends AbstractOioWorker<OioSocketChannel> {
    private static final Pattern SOCKET_CLOSED_MESSAGE = Pattern.compile("^.*(?:Socket.*closed).*$", 2);

    OioWorker(OioSocketChannel channel) {
        super(channel);
    }

    public void run() {
        if ((this.channel instanceof OioAcceptedSocketChannel) && ((OioSocketChannel) this.channel).isOpen()) {
            Channels.fireChannelConnected((Channel) this.channel, (SocketAddress) ((OioSocketChannel) this.channel).getRemoteAddress());
        }
        super.run();
    }

    /* access modifiers changed from: 0000 */
    public boolean process() throws IOException {
        PushbackInputStream in = ((OioSocketChannel) this.channel).getInputStream();
        int bytesToRead = in.available();
        if (bytesToRead > 0) {
            byte[] buf = new byte[bytesToRead];
            Channels.fireMessageReceived((Channel) this.channel, (Object) ((OioSocketChannel) this.channel).getConfig().getBufferFactory().getBuffer(buf, 0, in.read(buf)));
            return true;
        }
        int b = in.read();
        if (b < 0) {
            return false;
        }
        in.unread(b);
        return true;
    }

    static void write(OioSocketChannel channel, ChannelFuture future, Object message) {
        boolean iothread = isIoThread(channel);
        OutputStream out = channel.getOutputStream();
        if (out == null) {
            Exception e = new ClosedChannelException();
            future.setFailure(e);
            if (iothread) {
                Channels.fireExceptionCaught((Channel) channel, (Throwable) e);
            } else {
                Channels.fireExceptionCaughtLater((Channel) channel, (Throwable) e);
            }
        } else {
            int length = 0;
            try {
                if (message instanceof FileRegion) {
                    FileRegion fr = (FileRegion) message;
                    try {
                        synchronized (out) {
                            WritableByteChannel bchannel = java.nio.channels.Channels.newChannel(out);
                            do {
                                long i = fr.transferTo(bchannel, (long) length);
                                if (i <= 0) {
                                    break;
                                }
                                length = (int) (((long) length) + i);
                            } while (((long) length) < fr.getCount());
                        }
                    } finally {
                        if ((fr instanceof DefaultFileRegion) && ((DefaultFileRegion) fr).releaseAfterTransfer()) {
                            fr.releaseExternalResources();
                        }
                    }
                } else {
                    ChannelBuffer a = (ChannelBuffer) message;
                    length = a.readableBytes();
                    synchronized (out) {
                        a.getBytes(a.readerIndex(), out, length);
                    }
                }
                future.setSuccess();
                if (iothread) {
                    Channels.fireWriteComplete((Channel) channel, (long) length);
                    return;
                }
                Channels.fireWriteCompleteLater(channel, (long) length);
            } catch (Throwable th) {
                t = th;
                if ((t instanceof SocketException) && SOCKET_CLOSED_MESSAGE.matcher(String.valueOf(t.getMessage())).matches()) {
                    t = new ClosedChannelException();
                }
                future.setFailure(t);
                if (iothread) {
                    Channels.fireExceptionCaught((Channel) channel, t);
                } else {
                    Channels.fireExceptionCaughtLater((Channel) channel, t);
                }
            }
        }
    }
}