package org.jboss.netty.channel;

public class DefaultChildChannelStateEvent implements ChildChannelStateEvent {
    private final Channel childChannel;
    private final Channel parentChannel;

    public DefaultChildChannelStateEvent(Channel parentChannel2, Channel childChannel2) {
        if (parentChannel2 == null) {
            throw new NullPointerException("parentChannel");
        } else if (childChannel2 == null) {
            throw new NullPointerException("childChannel");
        } else {
            this.parentChannel = parentChannel2;
            this.childChannel = childChannel2;
        }
    }

    public Channel getChannel() {
        return this.parentChannel;
    }

    public ChannelFuture getFuture() {
        return Channels.succeededFuture(getChannel());
    }

    public Channel getChildChannel() {
        return this.childChannel;
    }

    public String toString() {
        String channelString = getChannel().toString();
        StringBuilder buf = new StringBuilder(channelString.length() + 32);
        buf.append(channelString);
        buf.append(getChildChannel().isOpen() ? " CHILD_OPEN: " : " CHILD_CLOSED: ");
        buf.append(getChildChannel().getId());
        return buf.toString();
    }
}