package org.jboss.netty.handler.codec.http.multipart;

import com.facebook.share.internal.ShareConstants;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.regex.Pattern;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.DefaultHttpChunk;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpConstants;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.multipart.HttpPostBodyUtil.TransferEncodingMechanism;
import org.jboss.netty.handler.stream.ChunkedInput;

public class HttpPostRequestEncoder implements ChunkedInput {
    private static final Map<Pattern, String> percentEncodings = new HashMap();
    private final List<InterfaceHttpData> bodyListDatas;
    private final Charset charset;
    private ChannelBuffer currentBuffer;
    private InterfaceHttpData currentData;
    private FileUpload currentFileUpload;
    private boolean duringMixedMode;
    private final EncoderMode encoderMode;
    private final HttpDataFactory factory;
    private long globalBodySize;
    private boolean headerFinalized;
    private boolean isChunked;
    private boolean isKey;
    private boolean isLastChunk;
    private boolean isLastChunkSent;
    private final boolean isMultipart;
    private ListIterator<InterfaceHttpData> iterator;
    private String multipartDataBoundary;
    private final List<InterfaceHttpData> multipartHttpDatas;
    private String multipartMixedBoundary;
    private final HttpRequest request;

    public enum EncoderMode {
        RFC1738,
        RFC3986
    }

    public static class ErrorDataEncoderException extends Exception {
        private static final long serialVersionUID = 5020247425493164465L;

        public ErrorDataEncoderException() {
        }

        public ErrorDataEncoderException(String msg) {
            super(msg);
        }

        public ErrorDataEncoderException(Throwable cause) {
            super(cause);
        }

        public ErrorDataEncoderException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    static {
        percentEncodings.put(Pattern.compile("\\*"), "%2A");
        percentEncodings.put(Pattern.compile("\\+"), "%20");
        percentEncodings.put(Pattern.compile("%7E"), "~");
    }

    public HttpPostRequestEncoder(HttpRequest request2, boolean multipart) throws ErrorDataEncoderException {
        this(new DefaultHttpDataFactory(16384), request2, multipart, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostRequestEncoder(HttpDataFactory factory2, HttpRequest request2, boolean multipart) throws ErrorDataEncoderException {
        this(factory2, request2, multipart, HttpConstants.DEFAULT_CHARSET);
    }

    public HttpPostRequestEncoder(HttpDataFactory factory2, HttpRequest request2, boolean multipart, Charset charset2) throws ErrorDataEncoderException {
        this(factory2, request2, multipart, charset2, EncoderMode.RFC1738);
    }

    public HttpPostRequestEncoder(HttpDataFactory factory2, HttpRequest request2, boolean multipart, Charset charset2, EncoderMode encoderMode2) throws ErrorDataEncoderException {
        this.isKey = true;
        if (factory2 == null) {
            throw new NullPointerException("factory");
        } else if (request2 == null) {
            throw new NullPointerException(ShareConstants.WEB_DIALOG_RESULT_PARAM_REQUEST_ID);
        } else if (charset2 == null) {
            throw new NullPointerException("charset");
        } else {
            HttpMethod method = request2.getMethod();
            if (method.equals(HttpMethod.POST) || method.equals(HttpMethod.PUT) || method.equals(HttpMethod.PATCH)) {
                this.request = request2;
                this.charset = charset2;
                this.factory = factory2;
                this.encoderMode = encoderMode2;
                this.bodyListDatas = new ArrayList();
                this.isLastChunk = false;
                this.isLastChunkSent = false;
                this.isMultipart = multipart;
                this.multipartHttpDatas = new ArrayList();
                if (this.isMultipart) {
                    initDataMultipart();
                    return;
                }
                return;
            }
            throw new ErrorDataEncoderException((String) "Cannot create a Encoder if not a POST");
        }
    }

    public void cleanFiles() {
        this.factory.cleanRequestHttpDatas(this.request);
    }

    public boolean isMultipart() {
        return this.isMultipart;
    }

    private void initDataMultipart() {
        this.multipartDataBoundary = getNewMultipartDelimiter();
    }

    private void initMixedMultipart() {
        this.multipartMixedBoundary = getNewMultipartDelimiter();
    }

    private static String getNewMultipartDelimiter() {
        return Long.toHexString(new Random().nextLong()).toLowerCase();
    }

    public List<InterfaceHttpData> getBodyListAttributes() {
        return this.bodyListDatas;
    }

    public void setBodyHttpDatas(List<InterfaceHttpData> datas) throws ErrorDataEncoderException {
        if (datas == null) {
            throw new NullPointerException("datas");
        }
        this.globalBodySize = 0;
        this.bodyListDatas.clear();
        this.currentFileUpload = null;
        this.duringMixedMode = false;
        this.multipartHttpDatas.clear();
        for (InterfaceHttpData data : datas) {
            addBodyHttpData(data);
        }
    }

    public void addBodyAttribute(String name, String value) throws ErrorDataEncoderException {
        if (name == null) {
            throw new NullPointerException("name");
        }
        String svalue = value;
        if (value == null) {
            svalue = "";
        }
        addBodyHttpData(this.factory.createAttribute(this.request, name, svalue));
    }

    public void addBodyFileUpload(String name, File file, String contentType, boolean isText) throws ErrorDataEncoderException {
        if (name == null) {
            throw new NullPointerException("name");
        } else if (file == null) {
            throw new NullPointerException("file");
        } else {
            String scontentType = contentType;
            String contentTransferEncoding = null;
            if (contentType == null) {
                if (isText) {
                    scontentType = "text/plain";
                } else {
                    scontentType = "application/octet-stream";
                }
            }
            if (!isText) {
                contentTransferEncoding = TransferEncodingMechanism.BINARY.value();
            }
            FileUpload fileUpload = this.factory.createFileUpload(this.request, name, file.getName(), scontentType, contentTransferEncoding, null, file.length());
            try {
                fileUpload.setContent(file);
                addBodyHttpData(fileUpload);
            } catch (IOException e) {
                throw new ErrorDataEncoderException((Throwable) e);
            }
        }
    }

    public void addBodyFileUploads(String name, File[] file, String[] contentType, boolean[] isText) throws ErrorDataEncoderException {
        if (file.length == contentType.length || file.length == isText.length) {
            for (int i = 0; i < file.length; i++) {
                addBodyFileUpload(name, file[i], contentType[i], isText[i]);
            }
            return;
        }
        throw new NullPointerException("Different array length");
    }

    public void addBodyHttpData(InterfaceHttpData data) throws ErrorDataEncoderException {
        boolean localMixed;
        if (this.headerFinalized) {
            throw new ErrorDataEncoderException((String) "Cannot add value once finalized");
        } else if (data == null) {
            throw new NullPointerException("data");
        } else {
            this.bodyListDatas.add(data);
            if (!this.isMultipart) {
                if (data instanceof Attribute) {
                    Attribute attribute = (Attribute) data;
                    try {
                        Attribute newattribute = this.factory.createAttribute(this.request, encodeAttribute(attribute.getName(), this.charset), encodeAttribute(attribute.getValue(), this.charset));
                        this.multipartHttpDatas.add(newattribute);
                        this.globalBodySize += ((long) (newattribute.getName().length() + 1)) + newattribute.length() + 1;
                    } catch (IOException e) {
                        throw new ErrorDataEncoderException((Throwable) e);
                    }
                } else if (data instanceof FileUpload) {
                    FileUpload fileUpload = (FileUpload) data;
                    Attribute newattribute2 = this.factory.createAttribute(this.request, encodeAttribute(fileUpload.getName(), this.charset), encodeAttribute(fileUpload.getFilename(), this.charset));
                    this.multipartHttpDatas.add(newattribute2);
                    this.globalBodySize += ((long) (newattribute2.getName().length() + 1)) + newattribute2.length() + 1;
                }
            } else if (data instanceof Attribute) {
                if (this.duringMixedMode) {
                    InternalAttribute internal = new InternalAttribute(this.charset);
                    internal.addValue("\r\n--" + this.multipartMixedBoundary + "--");
                    this.multipartHttpDatas.add(internal);
                    this.multipartMixedBoundary = null;
                    this.currentFileUpload = null;
                    this.duringMixedMode = false;
                }
                InternalAttribute internal2 = new InternalAttribute(this.charset);
                if (!this.multipartHttpDatas.isEmpty()) {
                    internal2.addValue("\r\n");
                }
                internal2.addValue("--" + this.multipartDataBoundary + "\r\n");
                Attribute attribute2 = (Attribute) data;
                internal2.addValue("Content-Disposition: form-data; name=\"" + attribute2.getName() + "\"\r\n");
                Charset localcharset = attribute2.getCharset();
                if (localcharset != null) {
                    internal2.addValue("Content-Type: text/plain; charset=" + localcharset + "\r\n");
                }
                internal2.addValue("\r\n");
                this.multipartHttpDatas.add(internal2);
                this.multipartHttpDatas.add(data);
                this.globalBodySize += attribute2.length() + ((long) internal2.size());
            } else if (data instanceof FileUpload) {
                FileUpload fileUpload2 = (FileUpload) data;
                InternalAttribute internal3 = new InternalAttribute(this.charset);
                if (!this.multipartHttpDatas.isEmpty()) {
                    internal3.addValue("\r\n");
                }
                if (this.duringMixedMode) {
                    if (this.currentFileUpload == null || !this.currentFileUpload.getName().equals(fileUpload2.getName())) {
                        internal3.addValue("--" + this.multipartMixedBoundary + "--");
                        this.multipartHttpDatas.add(internal3);
                        this.multipartMixedBoundary = null;
                        internal3 = new InternalAttribute(this.charset);
                        internal3.addValue("\r\n");
                        localMixed = false;
                        this.currentFileUpload = fileUpload2;
                        this.duringMixedMode = false;
                    } else {
                        localMixed = true;
                    }
                } else if (this.currentFileUpload == null || !this.currentFileUpload.getName().equals(fileUpload2.getName())) {
                    localMixed = false;
                    this.currentFileUpload = fileUpload2;
                    this.duringMixedMode = false;
                } else {
                    initMixedMultipart();
                    InternalAttribute pastAttribute = (InternalAttribute) this.multipartHttpDatas.get(this.multipartHttpDatas.size() - 2);
                    this.globalBodySize -= (long) pastAttribute.size();
                    pastAttribute.setValue(((("Content-Disposition: form-data; name=\"" + fileUpload2.getName() + "\"\r\n") + "Content-Type: multipart/mixed; boundary=" + this.multipartMixedBoundary + "\r\n\r\n") + "--" + this.multipartMixedBoundary + "\r\n") + "Content-Disposition: file; filename=\"" + fileUpload2.getFilename() + "\"\r\n", 1);
                    this.globalBodySize += (long) pastAttribute.size();
                    localMixed = true;
                    this.duringMixedMode = true;
                }
                if (localMixed) {
                    internal3.addValue("--" + this.multipartMixedBoundary + "\r\n");
                    internal3.addValue("Content-Disposition: file; filename=\"" + fileUpload2.getFilename() + "\"\r\n");
                } else {
                    internal3.addValue("--" + this.multipartDataBoundary + "\r\n");
                    internal3.addValue("Content-Disposition: form-data; name=\"" + fileUpload2.getName() + "\"; " + HttpPostBodyUtil.FILENAME + "=\"" + fileUpload2.getFilename() + "\"\r\n");
                }
                internal3.addValue("Content-Type: " + fileUpload2.getContentType());
                String contentTransferEncoding = fileUpload2.getContentTransferEncoding();
                if (contentTransferEncoding != null && contentTransferEncoding.equals(TransferEncodingMechanism.BINARY.value())) {
                    internal3.addValue("\r\nContent-Transfer-Encoding: " + TransferEncodingMechanism.BINARY.value() + "\r\n\r\n");
                } else if (fileUpload2.getCharset() != null) {
                    internal3.addValue("; charset=" + fileUpload2.getCharset() + "\r\n\r\n");
                } else {
                    internal3.addValue("\r\n\r\n");
                }
                this.multipartHttpDatas.add(internal3);
                this.multipartHttpDatas.add(data);
                this.globalBodySize += fileUpload2.length() + ((long) internal3.size());
            }
        }
    }

    public HttpRequest finalizeRequest() throws ErrorDataEncoderException {
        HttpHeaders headers = this.request.headers();
        if (!this.headerFinalized) {
            if (this.isMultipart) {
                InternalAttribute internal = new InternalAttribute(this.charset);
                if (this.duringMixedMode) {
                    internal.addValue("\r\n--" + this.multipartMixedBoundary + "--");
                }
                internal.addValue("\r\n--" + this.multipartDataBoundary + "--\r\n");
                this.multipartHttpDatas.add(internal);
                this.multipartMixedBoundary = null;
                this.currentFileUpload = null;
                this.duringMixedMode = false;
                this.globalBodySize += (long) internal.size();
            }
            this.headerFinalized = true;
            List<String> contentTypes = headers.getAll("Content-Type");
            List<String> transferEncoding = headers.getAll(Names.TRANSFER_ENCODING);
            if (contentTypes != null) {
                headers.remove("Content-Type");
                for (String contentType : contentTypes) {
                    if (!contentType.toLowerCase().startsWith(Values.MULTIPART_FORM_DATA) && !contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
                        headers.add((String) "Content-Type", (Object) contentType);
                    }
                }
            }
            if (this.isMultipart) {
                headers.add((String) "Content-Type", (Object) "multipart/form-data; boundary=" + this.multipartDataBoundary);
            } else {
                headers.add((String) "Content-Type", (Object) "application/x-www-form-urlencoded");
            }
            long realSize = this.globalBodySize;
            if (this.isMultipart) {
                this.iterator = this.multipartHttpDatas.listIterator();
            } else {
                realSize--;
                this.iterator = this.multipartHttpDatas.listIterator();
            }
            headers.set((String) "Content-Length", (Object) String.valueOf(realSize));
            if (realSize > 8096 || this.isMultipart) {
                this.isChunked = true;
                if (transferEncoding != null) {
                    headers.remove(Names.TRANSFER_ENCODING);
                    for (String v : transferEncoding) {
                        if (!v.equalsIgnoreCase(Values.CHUNKED)) {
                            headers.add((String) Names.TRANSFER_ENCODING, (Object) v);
                        }
                    }
                }
                headers.add((String) Names.TRANSFER_ENCODING, (Object) Values.CHUNKED);
                this.request.setContent(ChannelBuffers.EMPTY_BUFFER);
            } else {
                this.request.setContent(nextChunk().getContent());
            }
            return this.request;
        }
        throw new ErrorDataEncoderException((String) "Header already encoded");
    }

    public boolean isChunked() {
        return this.isChunked;
    }

    private String encodeAttribute(String s, Charset charset2) throws ErrorDataEncoderException {
        if (s == null) {
            return "";
        }
        try {
            String encoded = URLEncoder.encode(s, charset2.name());
            if (this.encoderMode != EncoderMode.RFC3986) {
                return encoded;
            }
            for (Entry<Pattern, String> entry : percentEncodings.entrySet()) {
                encoded = entry.getKey().matcher(encoded).replaceAll(entry.getValue());
            }
            return encoded;
        } catch (UnsupportedEncodingException e) {
            throw new ErrorDataEncoderException(charset2.name(), e);
        }
    }

    private ChannelBuffer fillChannelBuffer() {
        if (this.currentBuffer.readableBytes() > 8096) {
            ChannelBuffer slice = this.currentBuffer.slice(this.currentBuffer.readerIndex(), HttpPostBodyUtil.chunkSize);
            this.currentBuffer.skipBytes((int) HttpPostBodyUtil.chunkSize);
            return slice;
        }
        ChannelBuffer slice2 = this.currentBuffer;
        this.currentBuffer = null;
        return slice2;
    }

    private HttpChunk encodeNextChunkMultipart(int sizeleft) throws ErrorDataEncoderException {
        ChannelBuffer buffer;
        if (this.currentData == null) {
            return null;
        }
        if (this.currentData instanceof InternalAttribute) {
            buffer = ((InternalAttribute) this.currentData).toChannelBuffer();
            this.currentData = null;
        } else {
            if (this.currentData instanceof Attribute) {
                try {
                    buffer = ((Attribute) this.currentData).getChunk(sizeleft);
                } catch (IOException e) {
                    throw new ErrorDataEncoderException((Throwable) e);
                }
            } else {
                try {
                    buffer = ((HttpData) this.currentData).getChunk(sizeleft);
                } catch (IOException e2) {
                    throw new ErrorDataEncoderException((Throwable) e2);
                }
            }
            if (buffer.capacity() == 0) {
                this.currentData = null;
                return null;
            }
        }
        if (this.currentBuffer == null) {
            this.currentBuffer = buffer;
        } else {
            this.currentBuffer = ChannelBuffers.wrappedBuffer(this.currentBuffer, buffer);
        }
        if (this.currentBuffer.readableBytes() >= 8096) {
            return new DefaultHttpChunk(fillChannelBuffer());
        }
        this.currentData = null;
        return null;
    }

    private HttpChunk encodeNextChunkUrlEncoded(int sizeleft) throws ErrorDataEncoderException {
        if (this.currentData == null) {
            return null;
        }
        int size = sizeleft;
        if (this.isKey) {
            ChannelBuffer buffer = ChannelBuffers.wrappedBuffer(this.currentData.getName().getBytes());
            this.isKey = false;
            if (this.currentBuffer == null) {
                this.currentBuffer = ChannelBuffers.wrappedBuffer(buffer, ChannelBuffers.wrappedBuffer("=".getBytes()));
                size -= buffer.readableBytes() + 1;
            } else {
                this.currentBuffer = ChannelBuffers.wrappedBuffer(this.currentBuffer, buffer, ChannelBuffers.wrappedBuffer("=".getBytes()));
                size -= buffer.readableBytes() + 1;
            }
            if (this.currentBuffer.readableBytes() >= 8096) {
                return new DefaultHttpChunk(fillChannelBuffer());
            }
        }
        try {
            ChannelBuffer buffer2 = ((HttpData) this.currentData).getChunk(size);
            ChannelBuffer delimiter = null;
            if (buffer2.readableBytes() < size) {
                this.isKey = true;
                if (this.iterator.hasNext()) {
                    delimiter = ChannelBuffers.wrappedBuffer("&".getBytes());
                } else {
                    delimiter = null;
                }
            }
            if (buffer2.capacity() == 0) {
                this.currentData = null;
                if (this.currentBuffer == null) {
                    this.currentBuffer = delimiter;
                } else if (delimiter != null) {
                    this.currentBuffer = ChannelBuffers.wrappedBuffer(this.currentBuffer, delimiter);
                }
                if (this.currentBuffer.readableBytes() >= 8096) {
                    return new DefaultHttpChunk(fillChannelBuffer());
                }
                return null;
            }
            if (this.currentBuffer == null) {
                if (delimiter != null) {
                    this.currentBuffer = ChannelBuffers.wrappedBuffer(buffer2, delimiter);
                } else {
                    this.currentBuffer = buffer2;
                }
            } else if (delimiter != null) {
                this.currentBuffer = ChannelBuffers.wrappedBuffer(this.currentBuffer, buffer2, delimiter);
            } else {
                this.currentBuffer = ChannelBuffers.wrappedBuffer(this.currentBuffer, buffer2);
            }
            if (this.currentBuffer.readableBytes() >= 8096) {
                return new DefaultHttpChunk(fillChannelBuffer());
            }
            this.currentData = null;
            this.isKey = true;
            return null;
        } catch (IOException e) {
            throw new ErrorDataEncoderException((Throwable) e);
        }
    }

    public void close() throws Exception {
    }

    public HttpChunk nextChunk() throws ErrorDataEncoderException {
        HttpChunk chunk;
        if (this.isLastChunk) {
            this.isLastChunkSent = true;
            return new DefaultHttpChunk(ChannelBuffers.EMPTY_BUFFER);
        }
        int size = HttpPostBodyUtil.chunkSize;
        if (this.currentBuffer != null) {
            size = HttpPostBodyUtil.chunkSize - this.currentBuffer.readableBytes();
        }
        if (size <= 0) {
            return new DefaultHttpChunk(fillChannelBuffer());
        }
        if (this.currentData != null) {
            if (this.isMultipart) {
                HttpChunk chunk2 = encodeNextChunkMultipart(size);
                if (chunk2 != null) {
                    return chunk2;
                }
            } else {
                HttpChunk chunk3 = encodeNextChunkUrlEncoded(size);
                if (chunk3 != null) {
                    return chunk3;
                }
            }
            size = 8096 - this.currentBuffer.readableBytes();
        }
        if (!this.iterator.hasNext()) {
            this.isLastChunk = true;
            ChannelBuffer buffer = this.currentBuffer;
            this.currentBuffer = null;
            return new DefaultHttpChunk(buffer);
        }
        while (size > 0 && this.iterator.hasNext()) {
            this.currentData = this.iterator.next();
            if (this.isMultipart) {
                chunk = encodeNextChunkMultipart(size);
            } else {
                chunk = encodeNextChunkUrlEncoded(size);
            }
            if (chunk != null) {
                return chunk;
            }
            size = 8096 - this.currentBuffer.readableBytes();
        }
        this.isLastChunk = true;
        if (this.currentBuffer == null) {
            this.isLastChunkSent = true;
            return new DefaultHttpChunk(ChannelBuffers.EMPTY_BUFFER);
        }
        ChannelBuffer buffer2 = this.currentBuffer;
        this.currentBuffer = null;
        return new DefaultHttpChunk(buffer2);
    }

    public boolean isEndOfInput() throws Exception {
        return this.isLastChunkSent;
    }

    public boolean hasNextChunk() throws Exception {
        return !this.isLastChunkSent;
    }
}