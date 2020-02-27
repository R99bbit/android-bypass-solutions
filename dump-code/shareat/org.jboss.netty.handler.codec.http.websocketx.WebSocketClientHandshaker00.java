package org.jboss.netty.handler.codec.http.websocketx;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandler;
import org.jboss.netty.channel.DefaultChannelFuture;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequestEncoder;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseDecoder;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;

public class WebSocketClientHandshaker00 extends WebSocketClientHandshaker {
    private ChannelBuffer expectedChallengeResponseBytes;

    public WebSocketClientHandshaker00(URI webSocketURL, WebSocketVersion version, String subprotocol, Map<String, String> customHeaders) {
        this(webSocketURL, version, subprotocol, customHeaders, Long.MAX_VALUE);
    }

    public WebSocketClientHandshaker00(URI webSocketURL, WebSocketVersion version, String subprotocol, Map<String, String> customHeaders, long maxFramePayloadLength) {
        super(webSocketURL, version, subprotocol, customHeaders, maxFramePayloadLength);
    }

    public ChannelFuture handshake(Channel channel) {
        int spaces1 = WebSocketUtil.randomNumber(1, 12);
        int spaces2 = WebSocketUtil.randomNumber(1, 12);
        int number1 = WebSocketUtil.randomNumber(0, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED / spaces1);
        int number2 = WebSocketUtil.randomNumber(0, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED / spaces2);
        String key1 = Integer.toString(number1 * spaces1);
        String key2 = Integer.toString(number2 * spaces2);
        String key12 = insertRandomCharacters(key1);
        String key22 = insertRandomCharacters(key2);
        String key13 = insertSpaces(key12, spaces1);
        String key23 = insertSpaces(key22, spaces2);
        byte[] key3 = WebSocketUtil.randomBytes(8);
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(number1);
        byte[] number1Array = buffer.array();
        ByteBuffer buffer2 = ByteBuffer.allocate(4);
        buffer2.putInt(number2);
        byte[] number2Array = buffer2.array();
        byte[] challenge = new byte[16];
        System.arraycopy(number1Array, 0, challenge, 0, 4);
        System.arraycopy(number2Array, 0, challenge, 4, 4);
        System.arraycopy(key3, 0, challenge, 8, 8);
        this.expectedChallengeResponseBytes = WebSocketUtil.md5(ChannelBuffers.wrappedBuffer(challenge));
        URI wsURL = getWebSocketUrl();
        String path = wsURL.getPath();
        if (wsURL.getQuery() != null && wsURL.getQuery().length() > 0) {
            path = wsURL.getPath() + '?' + wsURL.getQuery();
        }
        if (path == null || path.length() == 0) {
            path = "/";
        }
        DefaultHttpRequest defaultHttpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, path);
        defaultHttpRequest.headers().add((String) "Upgrade", (Object) Values.WEBSOCKET);
        defaultHttpRequest.headers().add((String) "Connection", (Object) "Upgrade");
        defaultHttpRequest.headers().add((String) "Host", (Object) wsURL.getHost());
        int wsPort = wsURL.getPort();
        String originValue = "http://" + wsURL.getHost();
        if (!(wsPort == 80 || wsPort == 443)) {
            originValue = originValue + ':' + wsPort;
        }
        defaultHttpRequest.headers().add((String) Names.ORIGIN, (Object) originValue);
        defaultHttpRequest.headers().add((String) Names.SEC_WEBSOCKET_KEY1, (Object) key13);
        defaultHttpRequest.headers().add((String) Names.SEC_WEBSOCKET_KEY2, (Object) key23);
        String expectedSubprotocol = getExpectedSubprotocol();
        if (!(expectedSubprotocol == null || expectedSubprotocol.length() == 0)) {
            defaultHttpRequest.headers().add((String) Names.SEC_WEBSOCKET_PROTOCOL, (Object) expectedSubprotocol);
        }
        if (this.customHeaders != null) {
            for (Entry<String, String> e : this.customHeaders.entrySet()) {
                defaultHttpRequest.headers().add(e.getKey(), (Object) e.getValue());
            }
        }
        defaultHttpRequest.headers().set((String) "Content-Length", (Object) Integer.valueOf(key3.length));
        defaultHttpRequest.setContent(ChannelBuffers.copiedBuffer(key3));
        final ChannelFuture handshakeFuture = new DefaultChannelFuture(channel, false);
        ChannelFuture future = channel.write(defaultHttpRequest);
        AnonymousClass1 r0 = new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) {
                future.getChannel().getPipeline().replace(HttpRequestEncoder.class, (String) "ws-encoder", (ChannelHandler) new WebSocket00FrameEncoder());
                if (future.isSuccess()) {
                    handshakeFuture.setSuccess();
                } else {
                    handshakeFuture.setFailure(future.getCause());
                }
            }
        };
        future.addListener(r0);
        return handshakeFuture;
    }

    public void finishHandshake(Channel channel, HttpResponse response) {
        if (!response.getStatus().equals(new HttpResponseStatus(101, "WebSocket Protocol Handshake"))) {
            throw new WebSocketHandshakeException("Invalid handshake response status: " + response.getStatus());
        }
        String upgrade = response.headers().get("Upgrade");
        if (!Values.WEBSOCKET.equals(upgrade)) {
            throw new WebSocketHandshakeException("Invalid handshake response upgrade: " + upgrade);
        }
        String connection = response.headers().get("Connection");
        if (!"Upgrade".equals(connection)) {
            throw new WebSocketHandshakeException("Invalid handshake response connection: " + connection);
        } else if (!response.getContent().equals(this.expectedChallengeResponseBytes)) {
            throw new WebSocketHandshakeException("Invalid challenge");
        } else {
            setActualSubprotocol(response.headers().get(Names.SEC_WEBSOCKET_PROTOCOL));
            setHandshakeComplete();
            ((HttpResponseDecoder) channel.getPipeline().get(HttpResponseDecoder.class)).replace("ws-decoder", new WebSocket00FrameDecoder(getMaxFramePayloadLength()));
        }
    }

    private static String insertRandomCharacters(String key) {
        int count = WebSocketUtil.randomNumber(1, 12);
        char[] randomChars = new char[count];
        int randCount = 0;
        while (randCount < count) {
            int rand = (int) ((Math.random() * 126.0d) + 33.0d);
            if ((33 < rand && rand < 47) || (58 < rand && rand < 126)) {
                randomChars[randCount] = (char) rand;
                randCount++;
            }
        }
        for (int i = 0; i < count; i++) {
            int split = WebSocketUtil.randomNumber(0, key.length());
            String part1 = key.substring(0, split);
            key = part1 + randomChars[i] + key.substring(split);
        }
        return key;
    }

    private static String insertSpaces(String key, int spaces) {
        for (int i = 0; i < spaces; i++) {
            int split = WebSocketUtil.randomNumber(1, key.length() - 1);
            String part1 = key.substring(0, split);
            key = part1 + ' ' + key.substring(split);
        }
        return key;
    }
}