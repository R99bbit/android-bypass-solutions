package org.jboss.netty.handler.codec.http.multipart;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;
import org.jboss.netty.util.CharsetUtil;

public class InternalAttribute implements InterfaceHttpData {
    private final Charset charset;
    protected final List<String> value;

    @Deprecated
    public InternalAttribute() {
        this(CharsetUtil.UTF_8);
    }

    public InternalAttribute(Charset charset2) {
        this.value = new ArrayList();
        this.charset = charset2;
    }

    public HttpDataType getHttpDataType() {
        return HttpDataType.InternalAttribute;
    }

    @Deprecated
    public List<String> getValue() {
        return this.value;
    }

    public void addValue(String value2) {
        if (value2 == null) {
            throw new NullPointerException(Param.VALUE);
        }
        this.value.add(value2);
    }

    public void addValue(String value2, int rank) {
        if (value2 == null) {
            throw new NullPointerException(Param.VALUE);
        }
        this.value.add(rank, value2);
    }

    public void setValue(String value2, int rank) {
        if (value2 == null) {
            throw new NullPointerException(Param.VALUE);
        }
        this.value.set(rank, value2);
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
        if (o instanceof InternalAttribute) {
            return compareTo((InternalAttribute) o);
        }
        throw new ClassCastException("Cannot compare " + getHttpDataType() + " with " + o.getHttpDataType());
    }

    public int compareTo(InternalAttribute o) {
        return getName().compareToIgnoreCase(o.getName());
    }

    public int size() {
        int size = 0;
        for (String elt : this.value) {
            try {
                size += elt.getBytes(this.charset.name()).length;
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }
        return size;
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        for (String elt : this.value) {
            result.append(elt);
        }
        return result.toString();
    }

    public ChannelBuffer toChannelBuffer() {
        ChannelBuffer[] buffers = new ChannelBuffer[this.value.size()];
        for (int i = 0; i < buffers.length; i++) {
            buffers[i] = ChannelBuffers.copiedBuffer((CharSequence) this.value.get(i), this.charset);
        }
        return ChannelBuffers.wrappedBuffer(buffers);
    }

    public String getName() {
        return "InternalAttribute";
    }
}