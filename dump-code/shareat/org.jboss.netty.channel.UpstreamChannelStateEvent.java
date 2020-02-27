package org.jboss.netty.channel;

import com.nhn.android.naverlogin.ui.OAuthLoginInAppBrowserActivity.OAuthLoginInAppBrowserInIntentData;

public class UpstreamChannelStateEvent implements ChannelStateEvent {
    private final Channel channel;
    private final ChannelState state;
    private final Object value;

    public UpstreamChannelStateEvent(Channel channel2, ChannelState state2, Object value2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        } else if (state2 == null) {
            throw new NullPointerException(OAuthLoginInAppBrowserInIntentData.INTENT_PARAM_KEY_STATE);
        } else {
            this.channel = channel2;
            this.state = state2;
            this.value = value2;
        }
    }

    public Channel getChannel() {
        return this.channel;
    }

    public ChannelFuture getFuture() {
        return Channels.succeededFuture(getChannel());
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
                    buf.append(" CLOSED");
                    break;
                } else {
                    buf.append(" OPEN");
                    break;
                }
            case BOUND:
                if (getValue() == null) {
                    buf.append(" UNBOUND");
                    break;
                } else {
                    buf.append(" BOUND: ");
                    buf.append(getValue());
                    break;
                }
            case CONNECTED:
                if (getValue() == null) {
                    buf.append(" DISCONNECTED");
                    break;
                } else {
                    buf.append(" CONNECTED: ");
                    buf.append(getValue());
                    break;
                }
            case INTEREST_OPS:
                buf.append(" INTEREST_CHANGED");
                break;
            default:
                buf.append(getState().name());
                buf.append(": ");
                buf.append(getValue());
                break;
        }
        return buf.toString();
    }
}