package org.jboss.netty.handler.codec.http;

import com.kakao.auth.helper.ServerProtocol;
import org.jboss.netty.buffer.ChannelBuffer;

public class DefaultHttpChunk implements HttpChunk {
    private ChannelBuffer content;
    private boolean last;

    public DefaultHttpChunk(ChannelBuffer content2) {
        setContent(content2);
    }

    public ChannelBuffer getContent() {
        return this.content;
    }

    public void setContent(ChannelBuffer content2) {
        if (content2 == null) {
            throw new NullPointerException(ServerProtocol.CONTENT_KEY);
        }
        this.last = !content2.readable();
        this.content = content2;
    }

    public boolean isLast() {
        return this.last;
    }
}