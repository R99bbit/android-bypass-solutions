package org.jboss.netty.handler.ipfilter;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class IpSubnetFilterRule extends IpSubnet implements IpFilterRule {
    private boolean isAllowRule = true;

    public IpSubnetFilterRule(boolean allow) {
        this.isAllowRule = allow;
    }

    public IpSubnetFilterRule(boolean allow, InetAddress inetAddress, int cidrNetMask) throws UnknownHostException {
        super(inetAddress, cidrNetMask);
        this.isAllowRule = allow;
    }

    public IpSubnetFilterRule(boolean allow, InetAddress inetAddress, String netMask) throws UnknownHostException {
        super(inetAddress, netMask);
        this.isAllowRule = allow;
    }

    public IpSubnetFilterRule(boolean allow, String netAddress) throws UnknownHostException {
        super(netAddress);
        this.isAllowRule = allow;
    }

    public boolean isAllowRule() {
        return this.isAllowRule;
    }

    public boolean isDenyRule() {
        return !this.isAllowRule;
    }
}