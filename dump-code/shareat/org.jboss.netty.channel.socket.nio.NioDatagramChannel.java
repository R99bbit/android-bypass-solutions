package org.jboss.netty.channel.socket.nio;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.MembershipKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelSink;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.InternetProtocolFamily;
import org.jboss.netty.util.internal.DetectionUtil;

public class NioDatagramChannel extends AbstractNioChannel<DatagramChannel> implements org.jboss.netty.channel.socket.DatagramChannel {
    private final NioDatagramChannelConfig config = new DefaultNioDatagramChannelConfig((DatagramChannel) this.channel);
    private Map<InetAddress, List<MembershipKey>> memberships;

    public /* bridge */ /* synthetic */ int getInterestOps() {
        return super.getInterestOps();
    }

    public /* bridge */ /* synthetic */ InetSocketAddress getLocalAddress() {
        return super.getLocalAddress();
    }

    public /* bridge */ /* synthetic */ InetSocketAddress getRemoteAddress() {
        return super.getRemoteAddress();
    }

    NioDatagramChannel(ChannelFactory factory, ChannelPipeline pipeline, ChannelSink sink, NioDatagramWorker worker, InternetProtocolFamily family) {
        super(null, factory, pipeline, sink, worker, openNonBlockingChannel(family));
        Channels.fireChannelOpen((Channel) this);
    }

    private static DatagramChannel openNonBlockingChannel(InternetProtocolFamily family) {
        DatagramChannel channel;
        try {
            if (DetectionUtil.javaVersion() < 7 || family == null) {
                channel = DatagramChannel.open();
            } else {
                switch (family) {
                    case IPv4:
                        channel = DatagramChannel.open(ProtocolFamilyConverter.convert(family));
                        break;
                    case IPv6:
                        channel = DatagramChannel.open(ProtocolFamilyConverter.convert(family));
                        break;
                    default:
                        throw new IllegalArgumentException();
                }
            }
            channel.configureBlocking(false);
            return channel;
        } catch (IOException e) {
            throw new ChannelException("Failed to open a DatagramChannel.", e);
        }
    }

    public NioDatagramWorker getWorker() {
        return (NioDatagramWorker) super.getWorker();
    }

    public boolean isBound() {
        return isOpen() && ((DatagramChannel) this.channel).socket().isBound();
    }

    public boolean isConnected() {
        return ((DatagramChannel) this.channel).isConnected();
    }

    /* access modifiers changed from: protected */
    public boolean setClosed() {
        return super.setClosed();
    }

    public NioDatagramChannelConfig getConfig() {
        return this.config;
    }

    /* access modifiers changed from: 0000 */
    public DatagramChannel getDatagramChannel() {
        return (DatagramChannel) this.channel;
    }

    public ChannelFuture joinGroup(InetAddress multicastAddress) {
        try {
            return joinGroup(multicastAddress, NetworkInterface.getByInetAddress(getLocalAddress().getAddress()), null);
        } catch (SocketException e) {
            return Channels.failedFuture(this, e);
        }
    }

    public ChannelFuture joinGroup(InetSocketAddress multicastAddress, NetworkInterface networkInterface) {
        return joinGroup(multicastAddress.getAddress(), networkInterface, null);
    }

    public ChannelFuture joinGroup(InetAddress multicastAddress, NetworkInterface networkInterface, InetAddress source) {
        MembershipKey key;
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        } else if (multicastAddress == null) {
            throw new NullPointerException("multicastAddress");
        } else if (networkInterface == null) {
            throw new NullPointerException("networkInterface");
        } else {
            if (source == null) {
                try {
                    key = ((DatagramChannel) this.channel).join(multicastAddress, networkInterface);
                } catch (Throwable e) {
                    return Channels.failedFuture(this, e);
                }
            } else {
                key = ((DatagramChannel) this.channel).join(multicastAddress, networkInterface, source);
            }
            synchronized (this) {
                if (this.memberships == null) {
                    this.memberships = new HashMap();
                }
                List<MembershipKey> keys = this.memberships.get(multicastAddress);
                if (keys == null) {
                    keys = new ArrayList<>();
                    this.memberships.put(multicastAddress, keys);
                }
                keys.add(key);
            }
            return Channels.succeededFuture(this);
        }
    }

    public ChannelFuture leaveGroup(InetAddress multicastAddress) {
        try {
            return leaveGroup(multicastAddress, NetworkInterface.getByInetAddress(getLocalAddress().getAddress()), null);
        } catch (SocketException e) {
            return Channels.failedFuture(this, e);
        }
    }

    public ChannelFuture leaveGroup(InetSocketAddress multicastAddress, NetworkInterface networkInterface) {
        return leaveGroup(multicastAddress.getAddress(), networkInterface, null);
    }

    public ChannelFuture leaveGroup(InetAddress multicastAddress, NetworkInterface networkInterface, InetAddress source) {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        } else if (multicastAddress == null) {
            throw new NullPointerException("multicastAddress");
        } else if (networkInterface == null) {
            throw new NullPointerException("networkInterface");
        } else {
            synchronized (this) {
                if (this.memberships != null) {
                    List<MembershipKey> keys = this.memberships.get(multicastAddress);
                    if (keys != null) {
                        Iterator<MembershipKey> it = keys.iterator();
                        while (it.hasNext()) {
                            MembershipKey key = it.next();
                            if (networkInterface.equals(key.networkInterface()) && ((source == null && key.sourceAddress() == null) || (source != null && source.equals(key.sourceAddress())))) {
                                key.drop();
                                it.remove();
                            }
                        }
                        if (keys.isEmpty()) {
                            this.memberships.remove(multicastAddress);
                        }
                    }
                }
            }
            return Channels.succeededFuture(this);
        }
    }

    /* JADX WARNING: No exception handlers in catch block: Catch:{  } */
    public ChannelFuture block(InetAddress multicastAddress, NetworkInterface networkInterface, InetAddress sourceToBlock) {
        if (DetectionUtil.javaVersion() < 7) {
            throw new UnsupportedOperationException();
        } else if (multicastAddress == null) {
            throw new NullPointerException("multicastAddress");
        } else if (sourceToBlock == null) {
            throw new NullPointerException("sourceToBlock");
        } else if (networkInterface == null) {
            throw new NullPointerException("networkInterface");
        } else {
            synchronized (this) {
                if (this.memberships != null) {
                    for (MembershipKey key : this.memberships.get(multicastAddress)) {
                        if (networkInterface.equals(key.networkInterface())) {
                            try {
                                key.block(sourceToBlock);
                            } catch (IOException e) {
                                return Channels.failedFuture(this, e);
                            }
                        }
                    }
                }
            }
            return Channels.succeededFuture(this);
        }
    }

    public ChannelFuture block(InetAddress multicastAddress, InetAddress sourceToBlock) {
        try {
            block(multicastAddress, NetworkInterface.getByInetAddress(getLocalAddress().getAddress()), sourceToBlock);
            return Channels.succeededFuture(this);
        } catch (SocketException e) {
            return Channels.failedFuture(this, e);
        }
    }

    /* access modifiers changed from: 0000 */
    public InetSocketAddress getLocalSocketAddress() throws Exception {
        return (InetSocketAddress) ((DatagramChannel) this.channel).socket().getLocalSocketAddress();
    }

    /* access modifiers changed from: 0000 */
    public InetSocketAddress getRemoteSocketAddress() throws Exception {
        return (InetSocketAddress) ((DatagramChannel) this.channel).socket().getRemoteSocketAddress();
    }

    public ChannelFuture write(Object message, SocketAddress remoteAddress) {
        if (remoteAddress == null || remoteAddress.equals(getRemoteAddress())) {
            return super.write(message, null);
        }
        return super.write(message, remoteAddress);
    }
}