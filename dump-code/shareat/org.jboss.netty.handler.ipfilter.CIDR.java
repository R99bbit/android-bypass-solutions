package org.jboss.netty.handler.ipfilter;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.StringTokenizer;

public abstract class CIDR implements Comparable<CIDR> {
    protected InetAddress baseAddress;
    protected int cidrMask;

    public abstract boolean contains(InetAddress inetAddress);

    public abstract InetAddress getEndAddress();

    public static CIDR newCIDR(InetAddress baseAddress2, int cidrMask2) throws UnknownHostException {
        if (cidrMask2 < 0) {
            throw new UnknownHostException("Invalid mask length used: " + cidrMask2);
        } else if (baseAddress2 instanceof Inet4Address) {
            if (cidrMask2 <= 32) {
                return new CIDR4((Inet4Address) baseAddress2, cidrMask2);
            }
            throw new UnknownHostException("Invalid mask length used: " + cidrMask2);
        } else if (cidrMask2 <= 128) {
            return new CIDR6((Inet6Address) baseAddress2, cidrMask2);
        } else {
            throw new UnknownHostException("Invalid mask length used: " + cidrMask2);
        }
    }

    public static CIDR newCIDR(InetAddress baseAddress2, String scidrMask) throws UnknownHostException {
        int cidrMask2 = getNetMask(scidrMask);
        if (cidrMask2 < 0) {
            throw new UnknownHostException("Invalid mask length used: " + cidrMask2);
        } else if (!(baseAddress2 instanceof Inet4Address)) {
            int cidrMask3 = cidrMask2 + 96;
            if (cidrMask3 <= 128) {
                return new CIDR6((Inet6Address) baseAddress2, cidrMask3);
            }
            throw new UnknownHostException("Invalid mask length used: " + cidrMask3);
        } else if (cidrMask2 <= 32) {
            return new CIDR4((Inet4Address) baseAddress2, cidrMask2);
        } else {
            throw new UnknownHostException("Invalid mask length used: " + cidrMask2);
        }
    }

    public static CIDR newCIDR(String cidr) throws UnknownHostException {
        int mask;
        int p = cidr.indexOf(47);
        if (p < 0) {
            throw new UnknownHostException("Invalid CIDR notation used: " + cidr);
        }
        String addrString = cidr.substring(0, p);
        String maskString = cidr.substring(p + 1);
        InetAddress addr = addressStringToInet(addrString);
        if (maskString.indexOf(46) < 0) {
            mask = parseInt(maskString, -1);
        } else {
            mask = getNetMask(maskString);
            if (addr instanceof Inet6Address) {
                mask += 96;
            }
        }
        if (mask >= 0) {
            return newCIDR(addr, mask);
        }
        throw new UnknownHostException("Invalid mask length used: " + maskString);
    }

    public InetAddress getBaseAddress() {
        return this.baseAddress;
    }

    public int getMask() {
        return this.cidrMask;
    }

    public String toString() {
        return this.baseAddress.getHostAddress() + '/' + this.cidrMask;
    }

    public boolean equals(Object o) {
        if ((o instanceof CIDR) && compareTo((CIDR) o) == 0) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return this.baseAddress.hashCode();
    }

    private static InetAddress addressStringToInet(String addr) throws UnknownHostException {
        return InetAddress.getByName(addr);
    }

    private static int getNetMask(String netMask) {
        StringTokenizer nm = new StringTokenizer(netMask, ".");
        int i = 0;
        int[] netmask = new int[4];
        while (nm.hasMoreTokens()) {
            netmask[i] = Integer.parseInt(nm.nextToken());
            i++;
        }
        int mask1 = 0;
        for (int i2 = 0; i2 < 4; i2++) {
            mask1 += Integer.bitCount(netmask[i2]);
        }
        return mask1;
    }

    private static int parseInt(String intstr, int def) {
        Integer res;
        if (intstr == null) {
            return def;
        }
        try {
            res = Integer.decode(intstr);
        } catch (Exception e) {
            res = Integer.valueOf(def);
        }
        return res.intValue();
    }

    public static byte[] getIpV4FromIpV6(Inet6Address address) {
        byte[] baddr = address.getAddress();
        for (int i = 0; i < 9; i++) {
            if (baddr[i] != 0) {
                throw new IllegalArgumentException("This IPv6 address cannot be used in IPv4 context");
            }
        }
        if ((baddr[10] == 0 || baddr[10] == 255) && (baddr[11] == 0 || baddr[11] == 255)) {
            return new byte[]{baddr[12], baddr[13], baddr[14], baddr[15]};
        }
        throw new IllegalArgumentException("This IPv6 address cannot be used in IPv4 context");
    }

    public static byte[] getIpV6FromIpV4(Inet4Address address) {
        byte[] baddr = address.getAddress();
        return new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, baddr[0], baddr[1], baddr[2], baddr[3]};
    }
}