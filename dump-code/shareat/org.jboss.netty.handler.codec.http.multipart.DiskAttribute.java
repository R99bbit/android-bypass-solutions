package org.jboss.netty.handler.codec.http.multipart;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.io.IOException;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpConstants;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;

public class DiskAttribute extends AbstractDiskHttpData implements Attribute {
    public static String baseDirectory = null;
    public static boolean deleteOnExitTemporaryFile = true;
    public static final String postfix = ".att";
    public static final String prefix = "Attr_";

    public DiskAttribute(String name) {
        super(name, HttpConstants.DEFAULT_CHARSET, 0);
    }

    public DiskAttribute(String name, String value) throws IOException {
        super(name, HttpConstants.DEFAULT_CHARSET, 0);
        setValue(value);
    }

    public HttpDataType getHttpDataType() {
        return HttpDataType.Attribute;
    }

    public String getValue() throws IOException {
        return new String(get(), this.charset.name());
    }

    public void setValue(String value) throws IOException {
        if (value == null) {
            throw new NullPointerException(Param.VALUE);
        }
        byte[] bytes = value.getBytes(this.charset.name());
        checkSize((long) bytes.length);
        ChannelBuffer buffer = ChannelBuffers.wrappedBuffer(bytes);
        if (this.definedSize > 0) {
            this.definedSize = (long) buffer.readableBytes();
        }
        setContent(buffer);
    }

    public void addContent(ChannelBuffer buffer, boolean last) throws IOException {
        int localsize = buffer.readableBytes();
        checkSize(this.size + ((long) localsize));
        if (this.definedSize > 0 && this.definedSize < this.size + ((long) localsize)) {
            this.definedSize = this.size + ((long) localsize);
        }
        super.addContent(buffer, last);
    }

    public int hashCode() {
        return getName().hashCode();
    }

    public boolean equals(Object o) {
        if (!(o instanceof Attribute)) {
            return false;
        }
        return getName().equalsIgnoreCase(((Attribute) o).getName());
    }

    public int compareTo(InterfaceHttpData o) {
        if (o instanceof Attribute) {
            return compareTo((Attribute) o);
        }
        throw new ClassCastException("Cannot compare " + getHttpDataType() + " with " + o.getHttpDataType());
    }

    public int compareTo(Attribute o) {
        return getName().compareToIgnoreCase(o.getName());
    }

    public String toString() {
        try {
            return getName() + '=' + getValue();
        } catch (IOException e) {
            return getName() + "=IoException";
        }
    }

    /* access modifiers changed from: protected */
    public boolean deleteOnExit() {
        return deleteOnExitTemporaryFile;
    }

    /* access modifiers changed from: protected */
    public String getBaseDirectory() {
        return baseDirectory;
    }

    /* access modifiers changed from: protected */
    public String getDiskFilename() {
        return getName() + postfix;
    }

    /* access modifiers changed from: protected */
    public String getPostfix() {
        return postfix;
    }

    /* access modifiers changed from: protected */
    public String getPrefix() {
        return prefix;
    }
}