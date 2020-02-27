package org.jboss.netty.handler.codec.http.multipart;

import java.io.File;
import java.nio.charset.Charset;
import org.jboss.netty.handler.codec.http.multipart.InterfaceHttpData.HttpDataType;

public class DiskFileUpload extends AbstractDiskHttpData implements FileUpload {
    public static String baseDirectory = null;
    public static boolean deleteOnExitTemporaryFile = true;
    public static final String postfix = ".tmp";
    public static final String prefix = "FUp_";
    private String contentTransferEncoding;
    private String contentType;
    private String filename;

    public DiskFileUpload(String name, String filename2, String contentType2, String contentTransferEncoding2, Charset charset, long size) {
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
        return "Content-Disposition: form-data; name=\"" + getName() + "\"; " + HttpPostBodyUtil.FILENAME + "=\"" + this.filename + "\"\r\n" + "Content-Type" + ": " + this.contentType + (this.charset != null ? "; charset=" + this.charset + "\r\n" : "\r\n") + "Content-Length" + ": " + length() + "\r\n" + "Completed: " + isCompleted() + "\r\nIsInMemory: " + isInMemory() + "\r\nRealFile: " + this.file.getAbsolutePath() + " DefaultDeleteAfter: " + deleteOnExitTemporaryFile;
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
        return new File(this.filename).getName();
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