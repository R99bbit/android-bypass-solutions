package org.jboss.netty.channel.socket.http;

import java.util.Map;
import java.util.Map.Entry;
import javax.net.ssl.SSLContext;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.socket.SocketChannelConfig;
import org.jboss.netty.util.internal.ConversionUtil;

public final class HttpTunnelingSocketChannelConfig implements SocketChannelConfig {
    private final HttpTunnelingClientSocketChannel channel;
    private volatile boolean enableSslSessionCreation = true;
    private volatile String[] enabledSslCipherSuites;
    private volatile String[] enabledSslProtocols;
    private volatile String serverName;
    private volatile String serverPath = "/netty-tunnel";
    private volatile SSLContext sslContext;

    HttpTunnelingSocketChannelConfig(HttpTunnelingClientSocketChannel channel2) {
        this.channel = channel2;
    }

    public String getServerName() {
        return this.serverName;
    }

    public void setServerName(String serverName2) {
        this.serverName = serverName2;
    }

    public String getServerPath() {
        return this.serverPath;
    }

    public void setServerPath(String serverPath2) {
        if (serverPath2 == null) {
            throw new NullPointerException("serverPath");
        }
        this.serverPath = serverPath2;
    }

    public SSLContext getSslContext() {
        return this.sslContext;
    }

    public void setSslContext(SSLContext sslContext2) {
        this.sslContext = sslContext2;
    }

    public String[] getEnabledSslCipherSuites() {
        String[] suites = this.enabledSslCipherSuites;
        if (suites == null) {
            return null;
        }
        return (String[]) suites.clone();
    }

    public void setEnabledSslCipherSuites(String[] suites) {
        if (suites == null) {
            this.enabledSslCipherSuites = null;
        } else {
            this.enabledSslCipherSuites = (String[]) suites.clone();
        }
    }

    public String[] getEnabledSslProtocols() {
        String[] protocols = this.enabledSslProtocols;
        if (protocols == null) {
            return null;
        }
        return (String[]) protocols.clone();
    }

    public void setEnabledSslProtocols(String[] protocols) {
        if (protocols == null) {
            this.enabledSslProtocols = null;
        } else {
            this.enabledSslProtocols = (String[]) protocols.clone();
        }
    }

    public boolean isEnableSslSessionCreation() {
        return this.enableSslSessionCreation;
    }

    public void setEnableSslSessionCreation(boolean flag) {
        this.enableSslSessionCreation = flag;
    }

    public void setOptions(Map<String, Object> options) {
        for (Entry<String, Object> e : options.entrySet()) {
            setOption(e.getKey(), e.getValue());
        }
    }

    public boolean setOption(String key, Object value) {
        if (this.channel.realChannel.getConfig().setOption(key, value)) {
            return true;
        }
        if ("serverName".equals(key)) {
            setServerName(String.valueOf(value));
            return true;
        } else if ("serverPath".equals(key)) {
            setServerPath(String.valueOf(value));
            return true;
        } else if ("sslContext".equals(key)) {
            setSslContext((SSLContext) value);
            return true;
        } else if ("enabledSslCipherSuites".equals(key)) {
            setEnabledSslCipherSuites(ConversionUtil.toStringArray(value));
            return true;
        } else if ("enabledSslProtocols".equals(key)) {
            setEnabledSslProtocols(ConversionUtil.toStringArray(value));
            return true;
        } else if (!"enableSslSessionCreation".equals(key)) {
            return false;
        } else {
            setEnableSslSessionCreation(ConversionUtil.toBoolean(value));
            return true;
        }
    }

    public int getReceiveBufferSize() {
        return this.channel.realChannel.getConfig().getReceiveBufferSize();
    }

    public int getSendBufferSize() {
        return this.channel.realChannel.getConfig().getSendBufferSize();
    }

    public int getSoLinger() {
        return this.channel.realChannel.getConfig().getSoLinger();
    }

    public int getTrafficClass() {
        return this.channel.realChannel.getConfig().getTrafficClass();
    }

    public boolean isKeepAlive() {
        return this.channel.realChannel.getConfig().isKeepAlive();
    }

    public boolean isReuseAddress() {
        return this.channel.realChannel.getConfig().isReuseAddress();
    }

    public boolean isTcpNoDelay() {
        return this.channel.realChannel.getConfig().isTcpNoDelay();
    }

    public void setKeepAlive(boolean keepAlive) {
        this.channel.realChannel.getConfig().setKeepAlive(keepAlive);
    }

    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        this.channel.realChannel.getConfig().setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    public void setReceiveBufferSize(int receiveBufferSize) {
        this.channel.realChannel.getConfig().setReceiveBufferSize(receiveBufferSize);
    }

    public void setReuseAddress(boolean reuseAddress) {
        this.channel.realChannel.getConfig().setReuseAddress(reuseAddress);
    }

    public void setSendBufferSize(int sendBufferSize) {
        this.channel.realChannel.getConfig().setSendBufferSize(sendBufferSize);
    }

    public void setSoLinger(int soLinger) {
        this.channel.realChannel.getConfig().setSoLinger(soLinger);
    }

    public void setTcpNoDelay(boolean tcpNoDelay) {
        this.channel.realChannel.getConfig().setTcpNoDelay(tcpNoDelay);
    }

    public void setTrafficClass(int trafficClass) {
        this.channel.realChannel.getConfig().setTrafficClass(trafficClass);
    }

    public ChannelBufferFactory getBufferFactory() {
        return this.channel.realChannel.getConfig().getBufferFactory();
    }

    public int getConnectTimeoutMillis() {
        return this.channel.realChannel.getConfig().getConnectTimeoutMillis();
    }

    public ChannelPipelineFactory getPipelineFactory() {
        return this.channel.realChannel.getConfig().getPipelineFactory();
    }

    public void setBufferFactory(ChannelBufferFactory bufferFactory) {
        this.channel.realChannel.getConfig().setBufferFactory(bufferFactory);
    }

    public void setConnectTimeoutMillis(int connectTimeoutMillis) {
        this.channel.realChannel.getConfig().setConnectTimeoutMillis(connectTimeoutMillis);
    }

    public void setPipelineFactory(ChannelPipelineFactory pipelineFactory) {
        this.channel.realChannel.getConfig().setPipelineFactory(pipelineFactory);
    }
}