package org.jboss.netty.handler.codec.http.multipart;

import java.nio.charset.Charset;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;

public class MemoryFileUpload extends AbstractMemoryHttpData implements FileUpload {
    private String contentTransferEncoding;
    private String contentType;
    private String filename;

    public MemoryFileUpload(String name, String filename2, String contentType2, String contentTransferEncoding2, Charset charset, long size) {
        super(name, charset, size);
        setFilename(filename2);
        setContentType(contentType2);
        setContentTransferEncoding(contentTransferEncoding2);
    }

    public HttpDataType getHttpDataType() {
        return HttpDataType.FileUpload;
    }

    public String getFilename() {
        return this.filename;
    }

    public void setFilename(String filename2) {
        if (filename2 == null) {
            throw new NullPointerException(HttpPostBodyUtil.FILENAME);
        }
        this.filename = filename2;
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
        if (o instanceof FileUpload) {
            return compareTo((FileUpload) o);
        }
        throw new ClassCastException("Cannot compare " + getHttpDataType() + " with " + o.getHttpDataType());
    }

    public int compareTo(FileUpload o) {
        int v = getName().compareToIgnoreCase(o.getName());
        if (v != 0) {
        }
        return v;
    }

    public void setContentType(String contentType2) {
        if (contentType2 == null) {
            throw new NullPointerException("contentType");
        }
        this.contentType = contentType2;
    }

    public String getContentType() {
        return this.contentType;
    }

    public String getContentTransferEncoding() {
        return this.contentTransferEncoding;
    }

    public void setContentTransferEncoding(String contentTransferEncoding2) {
        this.contentTransferEncoding = contentTransferEncoding2;
    }

    public String toString() {
        return "Content-Disposition: form-data; name=\"" + getName() + "\"; " + HttpPostBodyUtil.FILENAME + "=\"" + this.filename + "\"\r\n" + "Content-Type" + ": " + this.contentType + (this.charset != null ? "; charset=" + this.charset + "\r\n" : "\r\n") + "Content-Length" + ": " + length() + "\r\n" + "Completed: " + isCompleted() + "\r\nIsInMemory: " + isInMemory();
    }
}