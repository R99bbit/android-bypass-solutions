package org.jboss.netty.handler.codec.socks;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.socks.SocksMessage.AddressType;
import org.jboss.netty.handler.codec.socks.SocksMessage.CmdStatus;
import org.jboss.netty.handler.codec.socks.SocksMessage.ProtocolVersion;

public class SocksCmdResponseDecoder extends ReplayingDecoder<State> {
    private static final String name = "SOCKS_CMD_RESPONSE_DECODER";
    private AddressType addressType;
    private CmdStatus cmdStatus;
    private int fieldLength;
    private String host;
    private SocksResponse msg = SocksCommonUtils.UNKNOWN_SOCKS_RESPONSE;
    private int port;
    private byte reserved;
    private ProtocolVersion version;

    public enum State {
        CHECK_PROTOCOL_VERSION,
        READ_CMD_HEADER,
        READ_CMD_ADDRESS
    }

    public static String getName() {
        return name;
    }

    public SocksCmdResponseDecoder() {
        super(State.CHECK_PROTOCOL_VERSION);
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0057, code lost:
        r3.host = org.jboss.netty.handler.codec.socks.SocksCommonUtils.intToIp(r6.readInt());
        r3.port = r6.readUnsignedShort();
        r3.msg = new org.jboss.netty.handler.codec.socks.SocksCmdResponse(r3.cmdStatus, r3.addressType);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0073, code lost:
        r3.fieldLength = r6.readByte();
        r3.host = r6.readBytes(r3.fieldLength).toString(org.jboss.netty.util.CharsetUtil.US_ASCII);
        r3.port = r6.readUnsignedShort();
        r3.msg = new org.jboss.netty.handler.codec.socks.SocksCmdResponse(r3.cmdStatus, r3.addressType);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x009a, code lost:
        r3.host = org.jboss.netty.handler.codec.socks.SocksCommonUtils.ipv6toStr(r6.readBytes(16).array());
        r3.port = r6.readUnsignedShort();
        r3.msg = new org.jboss.netty.handler.codec.socks.SocksCmdResponse(r3.cmdStatus, r3.addressType);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:2:0x000b, code lost:
        r4.getPipeline().remove((org.jboss.netty.channel.ChannelHandler) r3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:3:0x0014, code lost:
        return r3.msg;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x002a, code lost:
        r3.cmdStatus = org.jboss.netty.handler.codec.socks.SocksMessage.CmdStatus.fromByte(r6.readByte());
        r3.reserved = r6.readByte();
        r3.addressType = org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.fromByte(r6.readByte());
        checkpoint(org.jboss.netty.handler.codec.socks.SocksCmdResponseDecoder.State.READ_CMD_ADDRESS);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0053, code lost:
        switch(r3.addressType) {
            case org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.IPv4 :org.jboss.netty.handler.codec.socks.SocksMessage$AddressType: goto L_0x0057;
            case org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.DOMAIN :org.jboss.netty.handler.codec.socks.SocksMessage$AddressType: goto L_0x0073;
            case org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.IPv6 :org.jboss.netty.handler.codec.socks.SocksMessage$AddressType: goto L_0x009a;
            default: goto L_0x0056;
        };
     */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, State state) throws Exception {
        switch (state) {
            case CHECK_PROTOCOL_VERSION:
                this.version = ProtocolVersion.fromByte(buffer.readByte());
                if (this.version == ProtocolVersion.SOCKS5) {
                    checkpoint(State.READ_CMD_HEADER);
                    break;
                }
                break;
            case READ_CMD_HEADER:
                break;
            case READ_CMD_ADDRESS:
                break;
        }
    }
}