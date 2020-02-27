package org.jboss.netty.channel;

public class DefaultWriteCompletionEvent implements WriteCompletionEvent {
    private final Channel channel;
    private final long writtenAmount;

    public DefaultWriteCompletionEvent(Channel channel2, long writtenAmount2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        } else if (writtenAmount2 <= 0) {
            throw new IllegalArgumentException("writtenAmount must be a positive integer: " + writtenAmount2);
        } else {
            this.channel = channel2;
            this.writtenAmount = writtenAmount2;
        }
    }

    public Channel getChannel() {
        return this.channel;
    }

    public ChannelFuture getFuture() {
        return Channels.succeededFuture(getChannel());
    }

    public long getWrittenAmount() {
        return this.writtenAmount;
    }

    public String toString() {
        String channelString = getChannel().toString();
        StringBuilder buf = new StringBuilder(channelString.length() + 32);
        buf.append(channelString);
        buf.append(" WRITTEN_AMOUNT: ");
        buf.append(getWrittenAmount());
        return buf.toString();
    }
}