package org.jboss.netty.channel;

import com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig;
import java.util.Map;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.buffer.HeapChannelBufferFactory;

public class DefaultServerChannelConfig implements ChannelConfig {
    private volatile ChannelBufferFactory bufferFactory = HeapChannelBufferFactory.getInstance();
    private volatile ChannelPipelineFactory pipelineFactory;

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
        } else if (!NettyAsyncHttpProviderConfig.USE_DIRECT_BYTEBUFFER.equals(key)) {
            return false;
        } else {
            setBufferFactory((ChannelBufferFactory) value);
        }
        return true;
    }

    public ChannelPipelineFactory getPipelineFactory() {
        return this.pipelineFactory;
    }

    public void setPipelineFactory(ChannelPipelineFactory pipelineFactory2) {
        if (pipelineFactory2 == null) {
            throw new NullPointerException("pipelineFactory");
        }
        this.pipelineFactory = pipelineFactory2;
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

    public int getConnectTimeoutMillis() {
        return 0;
    }

    public void setConnectTimeoutMillis(int connectTimeoutMillis) {
    }
}