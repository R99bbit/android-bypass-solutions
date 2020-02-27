package org.jboss.netty.handler.codec.http.multipart;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.regex.Pattern;
import org.jboss.netty.handler.codec.http.HttpConstants;

public abstract class AbstractHttpData implements HttpData {
    private static final Pattern REPLACE_PATTERN = Pattern.compile("[\\r\\t]");
    private static final Pattern STRIP_PATTERN = Pattern.compile("(?:^\\s+|\\s+$|\\n)");
    protected Charset charset = HttpConstants.DEFAULT_CHARSET;
    protected boolean completed;
    protected long definedSize;
    protected long maxSize = -1;
    protected final String name;
    protected long size;

    protected AbstractHttpData(String name2, Charset charset2, long size2) {
        if (name2 == null) {
            throw new NullPointerException("name");
        }
        String name3 = STRIP_PATTERN.matcher(REPLACE_PATTERN.matcher(name2).replaceAll(" ")).replaceAll("");
        if (name3.length() == 0) {
            throw new IllegalArgumentException("empty name");
        }
        this.name = name3;
        if (charset2 != null) {
            setCharset(charset2);
        }
        this.definedSize = size2;
    }

    public void setMaxSize(long maxSize2) {
        this.maxSize = maxSize2;
    }

    public void checkSize(long newSize) throws IOException {
        if (this.maxSize >= 0 && newSize > this.maxSize) {
            throw new IOException("Size exceed allowed maximum capacity");
        }
    }

    public String getName() {
        return this.name;
    }

    public boolean isCompleted() {
        return this.completed;
    }

    public Charset getCharset() {
        return this.charset;
    }

    public void setCharset(Charset charset2) {
        if (charset2 == null) {
            throw new NullPointerException("charset");
        }
        this.charset = charset2;
    }

    public long length() {
        return this.size;
    }
}