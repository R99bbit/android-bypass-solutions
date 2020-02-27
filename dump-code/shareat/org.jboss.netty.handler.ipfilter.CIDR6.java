package org.jboss.netty.handler.ipfilter;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class CIDR6 extends CIDR {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(CIDR6.class);
    private BigInteger addressBigInt;
    private final BigInteger addressEndBigInt;

    protected CIDR6(Inet6Address newaddress, int newmask) {
        this.cidrMask = newmask;
        this.addressBigInt = ipv6AddressToBigInteger(newaddress);
        try {
            this.addressBigInt = this.addressBigInt.and(ipv6CidrMaskToMask(newmask));
            this.baseAddress = bigIntToIPv6Address(this.addressBigInt);
        } catch (UnknownHostException e) {
        }
        this.addressEndBigInt = this.addressBigInt.add(ipv6CidrMaskToBaseAddress(this.cidrMask)).subtract(BigInteger.ONE);
    }

    public InetAddress getEndAddress() {
        try {
            return bigIntToIPv6Address(this.addressEndBigInt);
        } catch (UnknownHostException e) {
            if (logger.isErrorEnabled()) {
                logger.error("invalid ip address calculated as an end address");
            }
            return null;
        }
    }

    public int compareTo(CIDR arg) {
        if (arg instanceof CIDR4) {
            int res = ipv6AddressToBigInteger(arg.baseAddress).compareTo(this.addressBigInt);
            if (res != 0) {
                return res;
            }
            if (arg.cidrMask == this.cidrMask) {
                return 0;
            }
            if (arg.cidrMask < this.cidrMask) {
                return -1;
            }
            return 1;
        }
        CIDR6 o = (CIDR6) arg;
        if (o.addressBigInt.equals(this.addressBigInt) && o.cidrMask == this.cidrMask) {
            return 0;
        }
        int res2 = o.addressBigInt.compareTo(this.addressBigInt);
        if (res2 != 0) {
            return res2;
        }
        if (o.cidrMask < this.cidrMask) {
            return -1;
        }
        return 1;
    }

    public boolean contains(InetAddress inetAddress) {
        BigInteger search = ipv6AddressToBigInteger(inetAddress);
        return search.compareTo(this.addressBigInt) >= 0 && search.compareTo(this.addressEndBigInt) <= 0;
    }

    private static BigInteger ipv6CidrMaskToBaseAddress(int cidrMask) {
        return BigInteger.ONE.shiftLeft(128 - cidrMask);
    }

    private static BigInteger ipv6CidrMaskToMask(int cidrMask) {
        return BigInteger.ONE.shiftLeft(128 - cidrMask).subtract(BigInteger.ONE).not();
    }

    private static BigInteger ipv6AddressToBigInteger(InetAddress addr) {
        byte[] ipv6;
        if (addr instanceof Inet4Address) {
            ipv6 = getIpV6FromIpV4((Inet4Address) addr);
        } else {
            ipv6 = addr.getAddress();
        }
        if (ipv6[0] == -1) {
            return new BigInteger(1, ipv6);
        }
        return new BigInteger(ipv6);
    }

    private static InetAddress bigIntToIPv6Address(BigInteger addr) throws UnknownHostException {
        byte[] a = new byte[16];
        byte[] b = addr.toByteArray();
        if (b.length > 16 && (b.length != 17 || b[0] != 0)) {
            throw new UnknownHostException("invalid IPv6 address (too big)");
        } else if (b.length == 16) {
            return InetAddress.getByAddress(b);
        } else {
            if (b.length == 17) {
                System.arraycopy(b, 1, a, 0, 16);
            } else {
                System.arraycopy(b, 0, a, 16 - b.length, b.length);
            }
            return InetAddress.getByAddress(a);
        }
    }
}