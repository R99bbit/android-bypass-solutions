package com.ning.http.client.providers.netty.timeout;

import com.ning.http.client.providers.netty.NettyAsyncHttpProvider;
import com.ning.http.client.providers.netty.NettyResponseFuture;
import com.ning.http.util.DateUtil;
import org.jboss.netty.util.Timeout;

public class RequestTimeoutTimerTask extends TimeoutTimerTask {
    public RequestTimeoutTimerTask(NettyResponseFuture<?> nettyResponseFuture, NettyAsyncHttpProvider provider, TimeoutsHolder timeoutsHolder) {
        super(nettyResponseFuture, provider, timeoutsHolder);
    }

    public void run(Timeout timeout) throws Exception {
        this.timeoutsHolder.cancel();
        if (!this.provider.isClose() && !this.nettyResponseFuture.isDone() && !this.nettyResponseFuture.isCancelled()) {
            expire("Request timeout of " + this.nettyResponseFuture.getRequestTimeoutInMs() + " ms", DateUtil.millisTime() - this.nettyResponseFuture.getStart());
            this.nettyResponseFuture.setRequestTimeoutReached();
        }
    }
}