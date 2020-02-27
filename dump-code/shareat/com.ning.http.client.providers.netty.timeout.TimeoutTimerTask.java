package com.ning.http.client.providers.netty.timeout;

import com.ning.http.client.providers.netty.NettyAsyncHttpProvider;
import com.ning.http.client.providers.netty.NettyResponseFuture;
import java.util.concurrent.TimeoutException;
import org.jboss.netty.util.TimerTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class TimeoutTimerTask implements TimerTask {
    private static final Logger LOGGER = LoggerFactory.getLogger(TimeoutTimerTask.class);
    protected final NettyResponseFuture<?> nettyResponseFuture;
    protected final NettyAsyncHttpProvider provider;
    protected final TimeoutsHolder timeoutsHolder;

    public TimeoutTimerTask(NettyResponseFuture<?> nettyResponseFuture2, NettyAsyncHttpProvider provider2, TimeoutsHolder timeoutsHolder2) {
        this.nettyResponseFuture = nettyResponseFuture2;
        this.provider = provider2;
        this.timeoutsHolder = timeoutsHolder2;
    }

    /* access modifiers changed from: protected */
    public void expire(String message, long time) {
        LOGGER.debug((String) "{} for {} after {} ms", message, this.nettyResponseFuture, Long.valueOf(time));
        this.provider.abort(this.nettyResponseFuture, new TimeoutException(message));
    }
}