package org.jboss.netty.channel;

import java.net.SocketAddress;
import java.util.Random;
import java.util.concurrent.ConcurrentMap;
import org.jboss.netty.util.internal.ConcurrentHashMap;

public abstract class AbstractChannel implements Channel {
    static final /* synthetic */ boolean $assertionsDisabled = (!AbstractChannel.class.desiredAssertionStatus());
    static final ConcurrentMap<Integer, Channel> allChannels = new ConcurrentHashMap();
    private static final Random random = new Random();
    private volatile Object attachment;
    private final ChannelCloseFuture closeFuture = new ChannelCloseFuture();
    private final ChannelFactory factory;
    private final Integer id;
    private volatile int interestOps = 1;
    private final Channel parent;
    private final ChannelPipeline pipeline;
    private String strVal;
    private boolean strValConnected;
    private final ChannelFuture succeededFuture = new SucceededChannelFuture(this);

    private final class ChannelCloseFuture extends DefaultChannelFuture {
        public ChannelCloseFuture() {
            super(AbstractChannel.this, false);
        }

        public boolean setSuccess() {
            return false;
        }

        public boolean setFailure(Throwable cause) {
            return false;
        }

        /* access modifiers changed from: 0000 */
        public boolean setClosed() {
            return super.setSuccess();
        }
    }

    private static Integer allocateId(Channel channel) {
        Integer id2 = Integer.valueOf(random.nextInt());
        while (allChannels.putIfAbsent(id2, channel) != null) {
            id2 = Integer.valueOf(id2.intValue() + 1);
        }
        return id2;
    }

    protected AbstractChannel(Channel parent2, ChannelFactory factory2, ChannelPipeline pipeline2, ChannelSink sink) {
        this.parent = parent2;
        this.factory = factory2;
        this.pipeline = pipeline2;
        this.id = allocateId(this);
        pipeline2.attach(this, sink);
    }

    protected AbstractChannel(Integer id2, Channel parent2, ChannelFactory factory2, ChannelPipeline pipeline2, ChannelSink sink) {
        this.id = id2;
        this.parent = parent2;
        this.factory = factory2;
        this.pipeline = pipeline2;
        pipeline2.attach(this, sink);
    }

    public final Integer getId() {
        return this.id;
    }

    public Channel getParent() {
        return this.parent;
    }

    public ChannelFactory getFactory() {
        return this.factory;
    }

    public ChannelPipeline getPipeline() {
        return this.pipeline;
    }

    /* access modifiers changed from: protected */
    public ChannelFuture getSucceededFuture() {
        return this.succeededFuture;
    }

    /* access modifiers changed from: protected */
    public ChannelFuture getUnsupportedOperationFuture() {
        return new FailedChannelFuture(this, new UnsupportedOperationException());
    }

    public final int hashCode() {
        return this.id.intValue();
    }

    public final boolean equals(Object o) {
        return this == o;
    }

    public final int compareTo(Channel o) {
        return getId().compareTo(o.getId());
    }

    public boolean isOpen() {
        return !this.closeFuture.isDone();
    }

    /* access modifiers changed from: protected */
    public boolean setClosed() {
        allChannels.remove(this.id);
        return this.closeFuture.setClosed();
    }

    public ChannelFuture bind(SocketAddress localAddress) {
        return Channels.bind(this, localAddress);
    }

    public ChannelFuture unbind() {
        return Channels.unbind(this);
    }

    public ChannelFuture close() {
        ChannelFuture returnedCloseFuture = Channels.close(this);
        if ($assertionsDisabled || this.closeFuture == returnedCloseFuture) {
            return this.closeFuture;
        }
        throw new AssertionError();
    }

    public ChannelFuture getCloseFuture() {
        return this.closeFuture;
    }

    public ChannelFuture connect(SocketAddress remoteAddress) {
        return Channels.connect(this, remoteAddress);
    }

    public ChannelFuture disconnect() {
        return Channels.disconnect(this);
    }

    public int getInterestOps() {
        return this.interestOps;
    }

    public ChannelFuture setInterestOps(int interestOps2) {
        return Channels.setInterestOps(this, interestOps2);
    }

    /* access modifiers changed from: protected */
    public void setInterestOpsNow(int interestOps2) {
        this.interestOps = interestOps2;
    }

    public boolean isReadable() {
        return (getInterestOps() & 1) != 0;
    }

    public boolean isWritable() {
        return (getInterestOps() & 4) == 0;
    }

    public ChannelFuture setReadable(boolean readable) {
        if (readable) {
            return setInterestOps(getInterestOps() | 1);
        }
        return setInterestOps(getInterestOps() & -2);
    }

    public ChannelFuture write(Object message) {
        return Channels.write(this, message);
    }

    public ChannelFuture write(Object message, SocketAddress remoteAddress) {
        return Channels.write((Channel) this, message, remoteAddress);
    }

    public Object getAttachment() {
        return this.attachment;
    }

    public void setAttachment(Object attachment2) {
        this.attachment = attachment2;
    }

    public String toString() {
        boolean connected = isConnected();
        if (this.strValConnected == connected && this.strVal != null) {
            return this.strVal;
        }
        StringBuilder buf = new StringBuilder(128);
        buf.append("[id: 0x");
        buf.append(getIdString());
        SocketAddress localAddress = getLocalAddress();
        SocketAddress remoteAddress = getRemoteAddress();
        if (remoteAddress != null) {
            buf.append(", ");
            if (getParent() == null) {
                buf.append(localAddress);
                buf.append(connected ? " => " : " :> ");
                buf.append(remoteAddress);
            } else {
                buf.append(remoteAddress);
                buf.append(connected ? " => " : " :> ");
                buf.append(localAddress);
            }
        } else if (localAddress != null) {
            buf.append(", ");
            buf.append(localAddress);
        }
        buf.append(']');
        String strVal2 = buf.toString();
        this.strVal = strVal2;
        this.strValConnected = connected;
        return strVal2;
    }

    private String getIdString() {
        String answer = Integer.toHexString(this.id.intValue());
        switch (answer.length()) {
            case 0:
                return "00000000";
            case 1:
                return "0000000" + answer;
            case 2:
                return "000000" + answer;
            case 3:
                return "00000" + answer;
            case 4:
                return "0000" + answer;
            case 5:
                return "000" + answer;
            case 6:
                return "00" + answer;
            case 7:
                return '0' + answer;
            default:
                return answer;
        }
    }
}