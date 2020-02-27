package org.jboss.netty.handler.codec.http.multipart;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.io.IOException;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpConstants;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;

public class MemoryAttribute extends AbstractMemoryHttpData implements Attribute {
    public MemoryAttribute(String name) {
        super(name, HttpConstants.DEFAULT_CHARSET, 0);
    }

    public MemoryAttribute(String name, String value) throws IOException {
        super(name, HttpConstants.DEFAULT_CHARSET, 0);
        setValue(value);
    }

    public HttpDataType getHttpDataType() {
        return HttpDataType.Attribute;
    }

    public String getValue() {
        return getChannelBuffer().toString(this.charset);
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

    public int compareTo(InterfaceHttpData other) {
        if (other instanceof Attribute) {
            return compareTo((Attribute) other);
        }
        throw new ClassCastException("Cannot compare " + getHttpDataType() + " with " + other.getHttpDataType());
    }

    public int compareTo(Attribute o) {
        return getName().compareToIgnoreCase(o.getName());
    }

    public String toString() {
        return getName() + '=' + getValue();
    }
}