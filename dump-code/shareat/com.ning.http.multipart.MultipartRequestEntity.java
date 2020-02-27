package com.ning.http.multipart;

import com.ning.http.client.FluentCaseInsensitiveStringsMap;
import com.ning.http.util.MiscUtil;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

public class MultipartRequestEntity implements RequestEntity {
    private static byte[] MULTIPART_CHARS = MultipartEncodingUtil.getAsciiBytes("-_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    private static final String MULTIPART_FORM_CONTENT_TYPE = "multipart/form-data";
    private final long contentLength;
    private final String contentType;
    private final byte[] multipartBoundary;
    protected final Part[] parts;

    public static byte[] generateMultipartBoundary() {
        Random rand = new Random();
        byte[] bytes = new byte[(rand.nextInt(11) + 30)];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = MULTIPART_CHARS[rand.nextInt(MULTIPART_CHARS.length)];
        }
        return bytes;
    }

    public MultipartRequestEntity(Part[] parts2, FluentCaseInsensitiveStringsMap requestHeaders) {
        if (parts2 == null) {
            throw new IllegalArgumentException("parts cannot be null");
        }
        this.parts = parts2;
        String contentTypeHeader = requestHeaders.getFirstValue("Content-Type");
        if (MiscUtil.isNonEmpty(contentTypeHeader)) {
            int boundaryLocation = contentTypeHeader.indexOf("boundary=");
            if (boundaryLocation != -1) {
                this.contentType = contentTypeHeader;
                this.multipartBoundary = MultipartEncodingUtil.getAsciiBytes(contentTypeHeader.substring("boundary=".length() + boundaryLocation).trim());
            } else {
                this.multipartBoundary = generateMultipartBoundary();
                this.contentType = computeContentType(contentTypeHeader);
            }
        } else {
            this.multipartBoundary = generateMultipartBoundary();
            this.contentType = computeContentType("multipart/form-data");
        }
        this.contentLength = Part.getLengthOfParts(parts2, this.multipartBoundary);
    }

    private String computeContentType(String base) {
        StringBuilder buffer = new StringBuilder(base);
        if (!base.endsWith(";")) {
            buffer.append(";");
        }
        return buffer.append(" boundary=").append(MultipartEncodingUtil.getAsciiString(this.multipartBoundary)).toString();
    }

    /* access modifiers changed from: protected */
    public byte[] getMultipartBoundary() {
        return this.multipartBoundary;
    }

    public boolean isRepeatable() {
        for (Part part : this.parts) {
            if (!part.isRepeatable()) {
                return false;
            }
        }
        return true;
    }

    public void writeRequest(OutputStream out) throws IOException {
        Part.sendParts(out, this.parts, this.multipartBoundary);
    }

    public long getContentLength() {
        return this.contentLength;
    }

    public String getContentType() {
        return this.contentType;
    }
}