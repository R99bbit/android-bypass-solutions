package com.ning.http.client.providers.netty.timeout;

import org.jboss.netty.util.Timeout;

public class TimeoutsHolder {
    public volatile Timeout idleConnectionTimeout;
    public volatile Timeout requestTimeout;

    public void cancel() {
        if (this.requestTimeout != null) {
            this.requestTimeout.cancel();
            this.requestTimeout = null;
        }
        if (this.idleConnectionTimeout != null) {
            this.idleConnectionTimeout.cancel();
            this.idleConnectionTimeout = null;
        }
    }
}