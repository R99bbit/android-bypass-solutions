package org.jboss.netty.handler.ipfilter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;

@Sharable
public class OneIpFilterHandler extends IpFilteringHandlerImpl {
    private final ConcurrentMap<InetAddress, Boolean> connectedSet = new ConcurrentHashMap();

    /* access modifiers changed from: protected */
    public boolean accept(ChannelHandlerContext ctx, ChannelEvent e, InetSocketAddress inetSocketAddress) throws Exception {
        InetAddress inetAddress = inetSocketAddress.getAddress();
        if (this.connectedSet.containsKey(inetAddress)) {
            return false;
        }
        this.connectedSet.put(inetAddress, Boolean.TRUE);
        return true;
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        super.handleUpstream(ctx, e);
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent evt = (ChannelStateEvent) e;
            if (evt.getState() == ChannelState.CONNECTED && evt.getValue() == null && isBlocked(ctx)) {
                this.connectedSet.remove(((InetSocketAddress) e.getChannel().getRemoteAddress()).getAddress());
            }
        }
    }
}