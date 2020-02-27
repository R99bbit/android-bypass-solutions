package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.StandardSocketOptions;
import java.nio.channels.DatagramChannel;
import java.util.Enumeration;
import java.util.Map;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.socket.DefaultDatagramChannelConfig;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.util.internal.ConversionUtil;
import org.jboss.netty.util.internal.DetectionUtil;

class DefaultNioDatagramChannelConfig extends DefaultDatagramChannelConfig implements NioDatagramChannelConfig {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(DefaultNioDatagramChannelConfig.class);
    private final DatagramChannel channel;
    private volatile int writeBufferHighWaterMark = 65536;
    private volatile int writeBufferLowWaterMark = 32768;
    private volatile int writeSpinCount = 16;

    DefaultNioDatagramChannelConfig(DatagramChannel channel2) {
        super(channel2.socket());
        this.channel = channel2;
    }

    public void setOptions(Map<String, Object> options) {
        super.setOptions(options);
        if (getWriteBufferHighWaterMark() < getWriteBufferLowWaterMark()) {
            setWriteBufferLowWaterMark0(getWriteBufferHighWaterMark() >>> 1);
            if (logger.isWarnEnabled()) {
                logger.warn("writeBufferLowWaterMark cannot be greater than writeBufferHighWaterMark; setting to the half of the writeBufferHighWaterMark.");
            }
        }
    }

    public boolean setOption(String key, Object value) {
        if (super.setOption(key, value)) {
            return true;
        }
        if ("writeBufferHighWaterMark".equals(key)) {
            setWriteBufferHighWaterMark0(ConversionUtil.toInt(value));
            return true;
        } else if ("writeBufferLowWaterMark".equals(key)) {
            setWriteBufferLowWaterMark0(ConversionUtil.toInt(value));
            return true;
        } else if (!"writeSpinCount".equals(key)) {
            return false;
        } else {
            setWriteSpinCount(ConversionUtil.toInt(value));
            return true;
        }
    }

    public int getWriteBufferHighWaterMark() {
        return this.writeBufferHighWaterMark;
    }

    public void setWriteBufferHighWaterMark(int writeBufferHighWaterMark2) {
        if (writeBufferHighWaterMark2 < getWriteBufferLowWaterMark()) {
            throw new IllegalArgumentException("writeBufferHighWaterMark cannot be less than writeBufferLowWaterMark (" + getWriteBufferLowWaterMark() + "): " + writeBufferHighWaterMark2);
        }
        setWriteBufferHighWaterMark0(writeBufferHighWaterMark2);
    }

    private void setWriteBufferHighWaterMark0(int writeBufferHighWaterMark2) {
        if (writeBufferHighWaterMark2 < 0) {
            throw new IllegalArgumentException("writeBufferHighWaterMark: " + writeBufferHighWaterMark2);
        }
        this.writeBufferHighWaterMark = writeBufferHighWaterMark2;
    }

    public int getWriteBufferLowWaterMark() {
        return this.writeBufferLowWaterMark;
    }

    public void setWriteBufferLowWaterMark(int writeBufferLowWaterMark2) {
        if (writeBufferLowWaterMark2 > getWriteBufferHighWaterMark()) {
            throw new IllegalArgumentException("writeBufferLowWaterMark cannot be greater than writeBufferHighWaterMark (" + getWriteBufferHighWaterMark() + "): " + writeBufferLowWaterMark2);
        }
        setWriteBufferLowWaterMark0(writeBufferLowWaterMark2);
    }

    private void setWriteBufferLowWaterMark0(int writeBufferLowWaterMark2) {
        if (writeBufferLowWaterMark2 < 0) {
            throw new IllegalArgumentException("writeBufferLowWaterMark: " + writeBufferLowWaterMark2);
        }
        this.writeBufferLowWaterMark = writeBufferLowWaterMark2;
    }

    public int getWriteSpinCount() {
        return this.writeSpinCount;
    }

    public void setWriteSpinCount(int writeSpinCount2) {
        if (writeSpinCount2 <= 0) {
            throw new IllegalArgumentException("writeSpinCount must be a positive integer.");
        }
        this.writeSpinCount = writeSpinCount2;
    }

    public void setNetworkInterface(NetworkInterface networkInterface) {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        }
        try {
            this.channel.setOption(StandardSocketOptions.IP_MULTICAST_IF, networkInterface);
        } catch (IOException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public NetworkInterface getNetworkInterface() {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        }
        try {
            return (NetworkInterface) this.channel.getOption(StandardSocketOptions.IP_MULTICAST_IF);
        } catch (IOException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public int getTimeToLive() {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        }
        try {
            return ((Integer) this.channel.getOption(StandardSocketOptions.IP_MULTICAST_TTL)).intValue();
        } catch (IOException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setTimeToLive(int ttl) {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        }
        try {
            this.channel.setOption(StandardSocketOptions.IP_MULTICAST_TTL, Integer.valueOf(ttl));
        } catch (IOException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public InetAddress getInterface() {
        NetworkInterface inf = getNetworkInterface();
        if (inf == null) {
            return null;
        }
        Enumeration<InetAddress> inetAddresses = inf.getInetAddresses();
        if (inetAddresses.hasMoreElements()) {
            return inetAddresses.nextElement();
        }
        return null;
    }

    public void setInterface(InetAddress interfaceAddress) {
        try {
            setNetworkInterface(NetworkInterface.getByInetAddress(interfaceAddress));
        } catch (SocketException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public boolean isLoopbackModeDisabled() {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        }
        try {
            return ((Boolean) this.channel.getOption(StandardSocketOptions.IP_MULTICAST_LOOP)).booleanValue();
        } catch (IOException e) {
            throw new ChannelException((Throwable) e);
        }
    }

    public void setLoopbackModeDisabled(boolean loopbackModeDisabled) {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        }
        try {
            this.channel.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, Boolean.valueOf(loopbackModeDisabled));
        } catch (IOException e) {
            throw new ChannelException((Throwable) e);
        }
    }
}