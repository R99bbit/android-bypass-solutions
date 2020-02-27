package org.jboss.netty.channel;

import com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig;
import java.util.Map;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.buffer.HeapChannelBufferFactory;
import org.jboss.netty.util.internal.ConversionUtil;

public class DefaultChannelConfig implements ChannelConfig {
    private volatile ChannelBufferFactory bufferFactory = HeapChannelBufferFactory.getInstance();
    private volatile int connectTimeoutMillis = 10000;

    public void setOptions(Map<String, Object> options) {
        for (Entry<String, Object> e : options.entrySet()) {
            setOption(e.getKey(), e.getValue());
        }
    }

    public boolean setOption(String key, Object value) {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if ("pipelineFactory".equals(key)) {
            setPipelineFactory((ChannelPipelineFactory) value);
        } else if ("connectTimeoutMillis".equals(key)) {
            setConnectTimeoutMillis(ConversionUtil.toInt(value));
        } else if (!NettyAsyncHttpProviderConfig.USE_DIRECT_BYTEBUFFER.equals(key)) {
            return false;
        } else {
            setBufferFactory((ChannelBufferFactory) value);
        }
        return true;
    }

    public int getConnectTimeoutMillis() {
        return this.connectTimeoutMillis;
    }

    public ChannelBufferFactory getBufferFactory() {
        return this.bufferFactory;
    }

    public void setBufferFactory(ChannelBufferFactory bufferFactory2) {
        if (bufferFactory2 == null) {
            throw new NullPointerException(NettyAsyncHttpProviderConfig.USE_DIRECT_BYTEBUFFER);
        }
        this.bufferFactory = bufferFactory2;
    }

    public ChannelPipelineFactory getPipelineFactory() {
        return null;
    }

    public void setConnectTimeoutMillis(int connectTimeoutMillis2) {
        if (connectTimeoutMillis2 < 0) {
            throw new IllegalArgumentException("connectTimeoutMillis: " + connectTimeoutMillis2);
        }
        this.connectTimeoutMillis = connectTimeoutMillis2;
    }

    public void setPipelineFactory(ChannelPipelineFactory pipelineFactory) {
    }
}