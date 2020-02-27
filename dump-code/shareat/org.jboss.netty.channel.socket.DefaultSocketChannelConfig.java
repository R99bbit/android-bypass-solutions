package org.jboss.netty.channel.socket;

import com.ning.http.client.providers.netty.NettyAsyncHttpProviderConfig;
import java.net.Socket;
import java.net.SocketException;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.DefaultChannelConfig;
import org.jboss.netty.util.internal.ConversionUtil;

public class DefaultSocketChannelConfig extends DefaultChannelConfig implements SocketChannelConfig {
    private final Socket socket;

    public DefaultSocketChannelConfig(Socket socket2) {
        if (socket2 == null) {
            throw new NullPointerException("socket");
        }
        this.socket = socket2;
    }

    public boolean setOption(String key, Object value) {
        if (super.setOption(key, value)) {
            return true;
        }
        if ("receiveBufferSize".equals(key)) {
            setReceiveBufferSize(ConversionUtil.toInt(value));
            return true;
        } else if ("sendBufferSize".equals(key)) {
            setSendBufferSize(ConversionUtil.toInt(value));
            return true;
        } else if ("tcpNoDelay".equals(key)) {
            setTcpNoDelay(ConversionUtil.toBoolean(value));
            return true;
        } else if ("keepAlive".equals(key)) {
            setKeepAlive(ConversionUtil.toBoolean(value));
            return true;
        } else if (NettyAsyncHttpProviderConfig.REUSE_ADDRESS.equals(key)) {
            setReuseAddress(ConversionUtil.toBoolean(value));
            return true;
        } else if ("soLinger".equals(key)) {
            setSoLinger(ConversionUtil.toInt(value));
            return true;
        } else if (!"trafficClass".equals(key)) {
            return false;
        } else {
            setTrafficClass(ConversionUtil.toInt(value));
            return true;
        }
    }

    public int getReceiveBufferSize() {
        try {
            return this.socket.getReceiveBufferSize();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public int getSendBufferSize() {
        try {
            return this.socket.getSendBufferSize();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public int getSoLinger() {
        try {
            return this.socket.getSoLinger();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public int getTrafficClass() {
        try {
            return this.socket.getTrafficClass();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public boolean isKeepAlive() {
        try {
            return this.socket.getKeepAlive();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public boolean isReuseAddress() {
        try {
            return this.socket.getReuseAddress();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public boolean isTcpNoDelay() {
        try {
            return this.socket.getTcpNoDelay();
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setKeepAlive(boolean keepAlive) {
        try {
            this.socket.setKeepAlive(keepAlive);
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        this.socket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    public void setReceiveBufferSize(int receiveBufferSize) {
        try {
            this.socket.setReceiveBufferSize(receiveBufferSize);
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setReuseAddress(boolean reuseAddress) {
        try {
            this.socket.setReuseAddress(reuseAddress);
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setSendBufferSize(int sendBufferSize) {
        try {
            this.socket.setSendBufferSize(sendBufferSize);
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setSoLinger(int soLinger) {
        if (soLinger < 0) {
            try {
                this.socket.setSoLinger(false, 0);
            } catch (SocketException e) {
                throw new ChannelException((Throwable) e);
            }
        } else {
            this.socket.setSoLinger(true, soLinger);
        }
    }

    public void setTcpNoDelay(boolean tcpNoDelay) {
        try {
            this.socket.setTcpNoDelay(tcpNoDelay);
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setTrafficClass(int trafficClass) {
        try {
            this.socket.setTrafficClass(trafficClass);
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }
}