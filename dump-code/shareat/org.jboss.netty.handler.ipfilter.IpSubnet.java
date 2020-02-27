package org.jboss.netty.handler.ipfilter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class IpSubnet implements IpSet, Comparable<IpSubnet> {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(IpSubnet.class);
    private final CIDR cidr;

    public IpSubnet() {
        this.cidr = null;
    }

    public IpSubnet(String netAddress) throws UnknownHostException {
        this.cidr = CIDR.newCIDR(netAddress);
    }

    public IpSubnet(InetAddress inetAddress, int cidrNetMask) throws UnknownHostException {
        this.cidr = CIDR.newCIDR(inetAddress, cidrNetMask);
    }

    public IpSubnet(InetAddress inetAddress, String netMask) throws UnknownHostException {
        this.cidr = CIDR.newCIDR(inetAddress, netMask);
    }

    public boolean contains(String ipAddr) throws UnknownHostException {
        return contains(InetAddress.getByName(ipAddr));
    }

    public boolean contains(InetAddress inetAddress) {
        if (this.cidr == null) {
            return true;
        }
        return this.cidr.contains(inetAddress);
    }

    public String toString() {
        return this.cidr.toString();
    }

    public boolean equals(Object o) {
        if (!(o instanceof IpSubnet)) {
            return false;
        }
        return ((IpSubnet) o).cidr.equals(this.cidr);
    }

    public int hashCode() {
        return this.cidr.hashCode();
    }

    public int compareTo(IpSubnet o) {
        return this.cidr.toString().compareTo(o.cidr.toString());
    }
}