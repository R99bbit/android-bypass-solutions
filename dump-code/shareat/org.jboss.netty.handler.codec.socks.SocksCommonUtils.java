package org.jboss.netty.handler.codec.socks;

final class SocksCommonUtils {
    static final /* synthetic */ boolean $assertionsDisabled = (!SocksCommonUtils.class.desiredAssertionStatus());
    private static final int FIRST_ADDRESS_OCTET_SHIFT = 24;
    private static final int SECOND_ADDRESS_OCTET_SHIFT = 16;
    private static final int THIRD_ADDRESS_OCTET_SHIFT = 8;
    public static final SocksRequest UNKNOWN_SOCKS_REQUEST = new UnknownSocksRequest();
    public static final SocksResponse UNKNOWN_SOCKS_RESPONSE = new UnknownSocksResponse();
    private static final int XOR_DEFAULT_VALUE = 255;
    private static final char[] ipv6conseqZeroFiller = {ipv6hextetSeparator, ipv6hextetSeparator};
    private static final char ipv6hextetSeparator = ':';

    private SocksCommonUtils() {
    }

    public static String intToIp(int i) {
        return String.valueOf((i >> 24) & 255) + '.' + ((i >> 16) & 255) + '.' + ((i >> 8) & 255) + '.' + (i & 255);
    }

    public static String ipv6toCompressedForm(byte[] src) {
        int curByte;
        if ($assertionsDisabled || src.length == 16) {
            int cmprHextet = -1;
            int cmprSize = 0;
            for (int hextet = 0; hextet < 8; hextet = (curByte / 2) + 1) {
                curByte = hextet * 2;
                int size = 0;
                while (curByte < src.length && src[curByte] == 0 && src[curByte + 1] == 0) {
                    curByte += 2;
                    size++;
                }
                if (size > cmprSize) {
                    cmprHextet = hextet;
                    cmprSize = size;
                }
            }
            if (cmprHextet == -1 || cmprSize < 2) {
                return ipv6toStr(src);
            }
            StringBuilder sb = new StringBuilder(39);
            ipv6toStr(sb, src, 0, cmprHextet);
            sb.append(ipv6conseqZeroFiller);
            ipv6toStr(sb, src, cmprHextet + cmprSize, 8);
            return sb.toString();
        }
        throw new AssertionError();
    }

    public static String ipv6toStr(byte[] src) {
        if ($assertionsDisabled || src.length == 16) {
            StringBuilder sb = new StringBuilder(39);
            ipv6toStr(sb, src, 0, 8);
            return sb.toString();
        }
        throw new AssertionError();
    }

    private static void ipv6toStr(StringBuilder sb, byte[] src, int fromHextet, int toHextet) {
        for (int i = fromHextet; i < toHextet; i++) {
            sb.append(Integer.toHexString(((src[i << 1] << 8) & 65280) | (src[(i << 1) + 1] & 255)));
            if (i < toHextet - 1) {
                sb.append(ipv6hextetSeparator);
            }
        }
    }
}