package org.jboss.netty.channel.socket.oio;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;

class OioDatagramWorker extends AbstractOioWorker<OioDatagramChannel> {
    OioDatagramWorker(OioDatagramChannel channel) {
        super(channel);
    }

    /* access modifiers changed from: 0000 */
    public boolean process() throws IOException {
        byte[] buf = new byte[((OioDatagramChannel) this.channel).getConfig().getReceiveBufferSizePredictor().nextReceiveBufferSize()];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        try {
            ((OioDatagramChannel) this.channel).socket.receive(packet);
            Channels.fireMessageReceived((Channel) this.channel, (Object) ((OioDatagramChannel) this.channel).getConfig().getBufferFactory().getBuffer(buf, 0, packet.getLength()), packet.getSocketAddress());
        } catch (InterruptedIOException e) {
        }
        return true;
    }

    static void write(OioDatagramChannel channel, ChannelFuture future, Object message, SocketAddress remoteAddress) {
        DatagramPacket packet;
        boolean iothread = isIoThread(channel);
        try {
            ChannelBuffer buf = (ChannelBuffer) message;
            int offset = buf.readerIndex();
            int length = buf.readableBytes();
            ByteBuffer nioBuf = buf.toByteBuffer();
            if (nioBuf.hasArray()) {
                packet = new DatagramPacket(nioBuf.array(), nioBuf.arrayOffset() + offset, length);
            } else {
                byte[] arrayBuf = new byte[length];
                buf.getBytes(0, arrayBuf);
                packet = new DatagramPacket(arrayBuf, length);
            }
            if (remoteAddress != null) {
                packet.setSocketAddress(remoteAddress);
            }
            channel.socket.send(packet);
            if (iothread) {
                Channels.fireWriteComplete((Channel) channel, (long) length);
            } else {
                Channels.fireWriteCompleteLater(channel, (long) length);
            }
            future.setSuccess();
        } catch (Throwable t) {
            future.setFailure(t);
            if (iothread) {
                Channels.fireExceptionCaught((Channel) channel, t);
            } else {
                Channels.fireExceptionCaughtLater((Channel) channel, t);
            }
        }
    }

    static void disconnect(OioDatagramChannel channel, ChannelFuture future) {
        boolean connected = channel.isConnected();
        boolean iothread = isIoThread(channel);
        try {
            channel.socket.disconnect();
            future.setSuccess();
            if (!connected) {
                return;
            }
            if (iothread) {
                Channels.fireChannelDisconnected((Channel) channel);
            } else {
                Channels.fireChannelDisconnectedLater(channel);
            }
        } catch (Throwable t) {
            future.setFailure(t);
            if (iothread) {
                Channels.fireExceptionCaught((Channel) channel, t);
            } else {
                Channels.fireExceptionCaughtLater((Channel) channel, t);
            }
        }
    }
}