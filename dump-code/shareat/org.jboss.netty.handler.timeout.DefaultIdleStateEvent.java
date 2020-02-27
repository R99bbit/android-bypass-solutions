package org.jboss.netty.handler.timeout;

import com.nhn.android.naverlogin.ui.OAuthLoginInAppBrowserActivity.OAuthLoginInAppBrowserInIntentData;
import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.Channels;

public class DefaultIdleStateEvent implements IdleStateEvent {
    private final Channel channel;
    private final long lastActivityTimeMillis;
    private final IdleState state;

    public DefaultIdleStateEvent(Channel channel2, IdleState state2, long lastActivityTimeMillis2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        } else if (state2 == null) {
            throw new NullPointerException(OAuthLoginInAppBrowserInIntentData.INTENT_PARAM_KEY_STATE);
        } else {
            this.channel = channel2;
            this.state = state2;
            this.lastActivityTimeMillis = lastActivityTimeMillis2;
        }
    }

    public Channel getChannel() {
        return this.channel;
    }

    public ChannelFuture getFuture() {
        return Channels.succeededFuture(getChannel());
    }

    public IdleState getState() {
        return this.state;
    }

    public long getLastActivityTimeMillis() {
        return this.lastActivityTimeMillis;
    }

    public String toString() {
        return getChannel().toString() + ' ' + getState() + " since " + DateFormat.getDateTimeInstance(3, 3, Locale.US).format(new Date(getLastActivityTimeMillis()));
    }
}