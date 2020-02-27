package org.jboss.netty.channel;

import com.nhn.android.naverlogin.ui.OAuthLoginInAppBrowserActivity.OAuthLoginInAppBrowserInIntentData;

public class DownstreamChannelStateEvent implements ChannelStateEvent {
    private final Channel channel;
    private final ChannelFuture future;
    private final ChannelState state;
    private final Object value;

    public DownstreamChannelStateEvent(Channel channel2, ChannelFuture future2, ChannelState state2, Object value2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        } else if (future2 == null) {
            throw new NullPointerException("future");
        } else if (state2 == null) {
            throw new NullPointerException(OAuthLoginInAppBrowserInIntentData.INTENT_PARAM_KEY_STATE);
        } else {
            this.channel = channel2;
            this.future = future2;
            this.state = state2;
            this.value = value2;
        }
    }

    public Channel getChannel() {
        return this.channel;
    }

    public ChannelFuture getFuture() {
        return this.future;
    }

    public ChannelState getState() {
        return this.state;
    }

    public Object getValue() {
        return this.value;
    }

    public String toString() {
        String channelString = getChannel().toString();
        StringBuilder buf = new StringBuilder(channelString.length() + 64);
        buf.append(channelString);
        switch (getState()) {
            case OPEN:
                if (!Boolean.TRUE.equals(getValue())) {
                    buf.append(" CLOSE");
                    break;
                } else {
                    buf.append(" OPEN");
                    break;
                }
            case BOUND:
                if (getValue() == null) {
                    buf.append(" UNBIND");
                    break;
                } else {
                    buf.append(" BIND: ");
                    buf.append(getValue());
                    break;
                }
            case CONNECTED:
                if (getValue() == null) {
                    buf.append(" DISCONNECT");
                    break;
                } else {
                    buf.append(" CONNECT: ");
                    buf.append(getValue());
                    break;
                }
            case INTEREST_OPS:
                buf.append(" CHANGE_INTEREST: ");
                buf.append(getValue());
                break;
            default:
                buf.append(' ');
                buf.append(getState().name());
                buf.append(": ");
                buf.append(getValue());
                break;
        }
        return buf.toString();
    }
}