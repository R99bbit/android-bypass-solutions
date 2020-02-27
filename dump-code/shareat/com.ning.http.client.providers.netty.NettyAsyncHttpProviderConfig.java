package com.ning.http.client.providers.netty;

import com.ning.http.client.AsyncHttpProviderConfig;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.netty.util.HashedWheelTimer;

public class NettyAsyncHttpProviderConfig implements AsyncHttpProviderConfig<String, Object> {
    public static final String BOSS_EXECUTOR_SERVICE = "bossExecutorService";
    public static final String DISABLE_NESTED_REQUEST = "disableNestedRequest";
    public static final String EXECUTE_ASYNC_CONNECT = "asyncConnect";
    public static final String HTTPS_CLIENT_CODEC_MAX_CHUNK_SIZE = "httpsClientCodecMaxChunkSize";
    public static final String HTTPS_CLIENT_CODEC_MAX_HEADER_SIZE = "httpsClientCodecMaxHeaderSize";
    public static final String HTTPS_CLIENT_CODEC_MAX_INITIAL_LINE_LENGTH = "httpsClientCodecMaxInitialLineLength";
    public static final String HTTP_CLIENT_CODEC_MAX_CHUNK_SIZE = "httpClientCodecMaxChunkSize";
    public static final String HTTP_CLIENT_CODEC_MAX_HEADER_SIZE = "httpClientCodecMaxHeaderSize";
    public static final String HTTP_CLIENT_CODEC_MAX_INITIAL_LINE_LENGTH = "httpClientCodecMaxInitialLineLength";
    public static final String REUSE_ADDRESS = "reuseAddress";
    public static final String SOCKET_CHANNEL_FACTORY = "socketChannelFactory";
    public static final String USE_BLOCKING_IO = "useBlockingIO";
    public static final String USE_DIRECT_BYTEBUFFER = "bufferFactory";
    private boolean disableZeroCopy;
    private HashedWheelTimer hashedWheelTimer;
    private final ConcurrentHashMap<String, Object> properties = new ConcurrentHashMap<>();

    public NettyAsyncHttpProviderConfig() {
        this.properties.put(REUSE_ADDRESS, "false");
    }

    public NettyAsyncHttpProviderConfig addProperty(String name, Object value) {
        this.properties.put(name, value);
        return this;
    }

    public Object getProperty(String name) {
        return this.properties.get(name);
    }

    public <T> T getProperty(String name, Class<T> type, T defaultValue) {
        Object value = this.properties.get(name);
        if (value == null || !type.isAssignableFrom(value.getClass())) {
            return defaultValue;
        }
        return type.cast(value);
    }

    public Object removeProperty(String name) {
        return this.properties.remove(name);
    }

    public Set<Entry<String, Object>> propertiesSet() {
        return this.properties.entrySet();
    }

    public void setDisableZeroCopy(boolean disableZeroCopy2) {
        this.disableZeroCopy = disableZeroCopy2;
    }

    public boolean isDisableZeroCopy() {
        return this.disableZeroCopy;
    }

    public HashedWheelTimer getHashedWheelTimer() {
        return this.hashedWheelTimer;
    }

    public void setHashedWheelTimer(HashedWheelTimer hashedWheelTimer2) {
        this.hashedWheelTimer = hashedWheelTimer2;
    }
}