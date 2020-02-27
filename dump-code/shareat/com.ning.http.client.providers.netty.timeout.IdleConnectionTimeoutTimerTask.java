package com.ning.http.client.providers.netty.timeout;

import com.ning.http.client.providers.netty.NettyAsyncHttpProvider;
import com.ning.http.client.providers.netty.NettyResponseFuture;
import com.ning.http.util.DateUtil;
import org.jboss.netty.util.Timeout;

public class IdleConnectionTimeoutTimerTask extends TimeoutTimerTask {
    private final long idleConnectionTimeout;
    private final long requestTimeoutInstant;

    public IdleConnectionTimeoutTimerTask(NettyResponseFuture<?> nettyResponseFuture, NettyAsyncHttpProvider provider, TimeoutsHolder timeoutsHolder, long requestTimeout, long idleConnectionTimeout2) {
        super(nettyResponseFuture, provider, timeoutsHolder);
        this.idleConnectionTimeout = idleConnectionTimeout2;
        this.requestTimeoutInstant = requestTimeout >= 0 ? nettyResponseFuture.getStart() + requestTimeout : Long.MAX_VALUE;
    }

    public void run(Timeout timeout) throws Exception {
        if (this.provider.isClose()) {
            this.timeoutsHolder.cancel();
        } else if (this.nettyResponseFuture.isDone() || this.nettyResponseFuture.isCancelled()) {
            this.timeoutsHolder.cancel();
        } else {
            long now = DateUtil.millisTime();
            long currentIdleConnectionTimeoutInstant = this.idleConnectionTimeout + this.nettyResponseFuture.getLastTouch();
            long durationBeforeCurrentIdleConnectionTimeout = currentIdleConnectionTimeoutInstant - now;
            if (durationBeforeCurrentIdleConnectionTimeout <= 0) {
                expire("Idle connection timeout of " + this.idleConnectionTimeout + " ms", now - this.nettyResponseFuture.getLastTouch());
                this.nettyResponseFuture.setIdleConnectionTimeoutReached();
            } else if (currentIdleConnectionTimeoutInstant < this.requestTimeoutInstant) {
                this.timeoutsHolder.idleConnectionTimeout = this.provider.newTimeoutInMs(this, durationBeforeCurrentIdleConnectionTimeout);
            } else {
                this.timeoutsHolder.idleConnectionTimeout = null;
            }
        }
    }
}