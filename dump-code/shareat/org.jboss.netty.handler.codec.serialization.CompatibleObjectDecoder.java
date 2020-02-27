package org.jboss.netty.handler.codec.serialization;

import java.io.InputStream;
import java.io.ObjectInputStream;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferInputStream;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;

@Deprecated
public class CompatibleObjectDecoder extends ReplayingDecoder<CompatibleObjectDecoderState> {
    private final SwitchableInputStream bin = new SwitchableInputStream();
    private ObjectInputStream oin;

    public CompatibleObjectDecoder() {
        super(CompatibleObjectDecoderState.READ_HEADER);
    }

    /* access modifiers changed from: protected */
    public ObjectInputStream newObjectInputStream(InputStream in) throws Exception {
        return new ObjectInputStream(in);
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, CompatibleObjectDecoderState state) throws Exception {
        this.bin.switchStream(new ChannelBufferInputStream(buffer));
        switch (state) {
            case READ_HEADER:
                this.oin = newObjectInputStream(this.bin);
                checkpoint(CompatibleObjectDecoderState.READ_OBJECT);
                break;
            case READ_OBJECT:
                break;
            default:
                throw new IllegalStateException("Unknown state: " + state);
        }
        return this.oin.readObject();
    }

    /* access modifiers changed from: protected */
    public Object decodeLast(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, CompatibleObjectDecoderState state) throws Exception {
        switch (buffer.readableBytes()) {
            case 0:
                return null;
            case 1:
                if (buffer.getByte(buffer.readerIndex()) == 121) {
                    buffer.skipBytes(1);
                    this.oin.close();
                    return null;
                }
                break;
        }
        Object decoded = decode(ctx, channel, buffer, state);
        this.oin.close();
        return decoded;
    }
}