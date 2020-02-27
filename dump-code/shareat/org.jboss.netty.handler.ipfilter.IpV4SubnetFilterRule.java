package org.jboss.netty.handler.ipfilter;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class IpV4SubnetFilterRule extends IpV4Subnet implements IpFilterRule {
    private boolean isAllowRule = true;

    public IpV4SubnetFilterRule(boolean allow) {
        this.isAllowRule = allow;
    }

    public IpV4SubnetFilterRule(boolean allow, InetAddress inetAddress, int cidrNetMask) {
        super(inetAddress, cidrNetMask);
        this.isAllowRule = allow;
    }

    public IpV4SubnetFilterRule(boolean allow, InetAddress inetAddress, String netMask) {
        super(inetAddress, netMask);
        this.isAllowRule = allow;
    }

    public IpV4SubnetFilterRule(boolean allow, String netAddress) throws UnknownHostException {
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