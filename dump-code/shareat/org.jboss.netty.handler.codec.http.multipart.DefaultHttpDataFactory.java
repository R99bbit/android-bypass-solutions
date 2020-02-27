package org.jboss.netty.handler.codec.http.multipart;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.netty.handler.codec.http.HttpRequest;

public class DefaultHttpDataFactory implements HttpDataFactory {
    public static final long MAXSIZE = -1;
    public static final long MINSIZE = 16384;
    private final boolean checkSize;
    private long maxSize;
    private long minSize;
    private final ConcurrentHashMap<HttpRequest, List<HttpData>> requestFileDeleteMap;
    private final boolean useDisk;

    public DefaultHttpDataFactory() {
        this.maxSize = -1;
        this.requestFileDeleteMap = new ConcurrentHashMap<>();
        this.useDisk = false;
        this.checkSize = true;
        this.minSize = 16384;
    }

    public DefaultHttpDataFactory(boolean useDisk2) {
        this.maxSize = -1;
        this.requestFileDeleteMap = new ConcurrentHashMap<>();
        this.useDisk = useDisk2;
        this.checkSize = false;
    }

    public DefaultHttpDataFactory(long minSize2) {
        this.maxSize = -1;
        this.requestFileDeleteMap = new ConcurrentHashMap<>();
        this.useDisk = false;
        this.checkSize = true;
        this.minSize = minSize2;
    }

    public void setMaxLimit(long max) {
        this.maxSize = max;
    }

    private List<HttpData> getList(HttpRequest request) {
        List<HttpData> list = this.requestFileDeleteMap.get(request);
        if (list != null) {
            return list;
        }
        List<HttpData> list2 = new ArrayList<>();
        this.requestFileDeleteMap.put(request, list2);
        return list2;
    }

    public Attribute createAttribute(HttpRequest request, String name) {
        if (this.useDisk) {
            Attribute attribute = new DiskAttribute(name);
            attribute.setMaxSize(this.maxSize);
            getList(request).add(attribute);
            return attribute;
        } else if (this.checkSize) {
            Attribute attribute2 = new MixedAttribute(name, this.minSize);
            attribute2.setMaxSize(this.maxSize);
            getList(request).add(attribute2);
            return attribute2;
        } else {
            MemoryAttribute attribute3 = new MemoryAttribute(name);
            attribute3.setMaxSize(this.maxSize);
            return attribute3;
        }
    }

    private void checkHttpDataSize(HttpData data) {
        try {
            data.checkSize(data.length());
        } catch (IOException e) {
            throw new IllegalArgumentException("Attribute bigger than maxSize allowed");
        }
    }

    public Attribute createAttribute(HttpRequest request, String name, String value) {
        Attribute attribute;
        if (this.useDisk) {
            try {
                attribute = new DiskAttribute(name, value);
                attribute.setMaxSize(this.maxSize);
            } catch (IOException e) {
                attribute = new MixedAttribute(name, value, this.minSize);
                attribute.setMaxSize(this.maxSize);
            }
            checkHttpDataSize(attribute);
            getList(request).add(attribute);
            return attribute;
        } else if (this.checkSize) {
            Attribute attribute2 = new MixedAttribute(name, value, this.minSize);
            attribute2.setMaxSize(this.maxSize);
            checkHttpDataSize(attribute2);
            getList(request).add(attribute2);
            return attribute2;
        } else {
            try {
                MemoryAttribute attribute3 = new MemoryAttribute(name, value);
                attribute3.setMaxSize(this.maxSize);
                checkHttpDataSize(attribute3);
                return attribute3;
            } catch (IOException e2) {
                throw new IllegalArgumentException(e2);
            }
        }
    }

    public FileUpload createFileUpload(HttpRequest request, String name, String filename, String contentType, String contentTransferEncoding, Charset charset, long size) {
        if (this.useDisk) {
            FileUpload fileUpload = new DiskFileUpload(name, filename, contentType, contentTransferEncoding, charset, size);
            fileUpload.setMaxSize(this.maxSize);
            checkHttpDataSize(fileUpload);
            getList(request).add(fileUpload);
            return fileUpload;
        } else if (this.checkSize) {
            FileUpload fileUpload2 = new MixedFileUpload(name, filename, contentType, contentTransferEncoding, charset, size, this.minSize);
            fileUpload2.setMaxSize(this.maxSize);
            checkHttpDataSize(fileUpload2);
            getList(request).add(fileUpload2);
            return fileUpload2;
        } else {
            MemoryFileUpload fileUpload3 = new MemoryFileUpload(name, filename, contentType, contentTransferEncoding, charset, size);
            fileUpload3.setMaxSize(this.maxSize);
            checkHttpDataSize(fileUpload3);
            return fileUpload3;
        }
    }

    public void removeHttpDataFromClean(HttpRequest request, InterfaceHttpData data) {
        if (data instanceof HttpData) {
            getList(request).remove(data);
        }
    }

    public void cleanRequestHttpDatas(HttpRequest request) {
        List<HttpData> fileToDelete = this.requestFileDeleteMap.remove(request);
        if (fileToDelete != null) {
            for (HttpData data : fileToDelete) {
                data.delete();
            }
            fileToDelete.clear();
        }
    }

    public void cleanAllHttpDatas() {
        for (HttpRequest request : this.requestFileDeleteMap.keySet()) {
            List<HttpData> fileToDelete = this.requestFileDeleteMap.get(request);
            if (fileToDelete != null) {
                for (HttpData data : fileToDelete) {
                    data.delete();
                }
                fileToDelete.clear();
            }
            this.requestFileDeleteMap.remove(request);
        }
    }
}