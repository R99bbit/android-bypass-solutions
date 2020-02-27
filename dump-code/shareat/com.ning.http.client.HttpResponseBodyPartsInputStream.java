package com.ning.http.client;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class HttpResponseBodyPartsInputStream extends InputStream {
    private byte[] active;
    private int available = 0;
    private int bytePos = -1;
    private int currentPos = 0;
    private final List<HttpResponseBodyPart> parts;

    public HttpResponseBodyPartsInputStream(List<HttpResponseBodyPart> parts2) {
        this.parts = parts2;
        this.active = parts2.get(0).getBodyPartBytes();
        computeLength(parts2);
    }

    private void computeLength(List<HttpResponseBodyPart> parts2) {
        if (this.available == 0) {
            for (HttpResponseBodyPart p : parts2) {
                this.available += p.getBodyPartBytes().length;
            }
        }
    }

    public int available() throws IOException {
        return this.available;
    }

    public int read() throws IOException {
        int i = this.bytePos + 1;
        this.bytePos = i;
        if (i >= this.active.length) {
            int i2 = this.currentPos + 1;
            this.currentPos = i2;
            if (i2 >= this.parts.size()) {
                return -1;
            }
            this.bytePos = 0;
            this.active = this.parts.get(this.currentPos).getBodyPartBytes();
        }
        return this.active[this.bytePos] & 255;
    }
}