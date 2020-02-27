package com.ning.http.client.providers.netty;

import com.ning.http.client.RandomAccessBody;
import java.io.IOException;
import java.nio.channels.WritableByteChannel;
import org.jboss.netty.channel.FileRegion;

class BodyFileRegion implements FileRegion {
    private final RandomAccessBody body;

    public BodyFileRegion(RandomAccessBody body2) {
        if (body2 == null) {
            throw new IllegalArgumentException("no body specified");
        }
        this.body = body2;
    }

    public long getPosition() {
        return 0;
    }

    public long getCount() {
        return this.body.getContentLength();
    }

    public long transferTo(WritableByteChannel target, long position) throws IOException {
        return this.body.transferTo(position, Long.MAX_VALUE, target);
    }

    public void releaseExternalResources() {
        try {
            this.body.close();
        } catch (IOException e) {
        }
    }
}