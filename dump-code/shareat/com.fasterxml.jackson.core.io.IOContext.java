package com.fasterxml.jackson.core.io;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.util.BufferRecycler;
import com.fasterxml.jackson.core.util.BufferRecycler.ByteBufferType;
import com.fasterxml.jackson.core.util.BufferRecycler.CharBufferType;
import com.fasterxml.jackson.core.util.TextBuffer;

public final class IOContext {
    protected byte[] _base64Buffer = null;
    protected final BufferRecycler _bufferRecycler;
    protected char[] _concatCBuffer = null;
    protected JsonEncoding _encoding;
    protected final boolean _managedResource;
    protected char[] _nameCopyBuffer = null;
    protected byte[] _readIOBuffer = null;
    protected final Object _sourceRef;
    protected char[] _tokenCBuffer = null;
    protected byte[] _writeEncodingBuffer = null;

    public IOContext(BufferRecycler bufferRecycler, Object obj, boolean z) {
        this._bufferRecycler = bufferRecycler;
        this._sourceRef = obj;
        this._managedResource = z;
    }

    public void setEncoding(JsonEncoding jsonEncoding) {
        this._encoding = jsonEncoding;
    }

    public Object getSourceReference() {
        return this._sourceRef;
    }

    public JsonEncoding getEncoding() {
        return this._encoding;
    }

    public boolean isResourceManaged() {
        return this._managedResource;
    }

    public TextBuffer constructTextBuffer() {
        return new TextBuffer(this._bufferRecycler);
    }

    public byte[] allocReadIOBuffer() {
        _verifyAlloc(this._readIOBuffer);
        byte[] allocByteBuffer = this._bufferRecycler.allocByteBuffer(ByteBufferType.READ_IO_BUFFER);
        this._readIOBuffer = allocByteBuffer;
        return allocByteBuffer;
    }

    public byte[] allocWriteEncodingBuffer() {
        _verifyAlloc(this._writeEncodingBuffer);
        byte[] allocByteBuffer = this._bufferRecycler.allocByteBuffer(ByteBufferType.WRITE_ENCODING_BUFFER);
        this._writeEncodingBuffer = allocByteBuffer;
        return allocByteBuffer;
    }

    public byte[] allocBase64Buffer() {
        _verifyAlloc(this._base64Buffer);
        byte[] allocByteBuffer = this._bufferRecycler.allocByteBuffer(ByteBufferType.BASE64_CODEC_BUFFER);
        this._base64Buffer = allocByteBuffer;
        return allocByteBuffer;
    }

    public char[] allocTokenBuffer() {
        _verifyAlloc(this._tokenCBuffer);
        char[] allocCharBuffer = this._bufferRecycler.allocCharBuffer(CharBufferType.TOKEN_BUFFER);
        this._tokenCBuffer = allocCharBuffer;
        return allocCharBuffer;
    }

    public char[] allocConcatBuffer() {
        _verifyAlloc(this._concatCBuffer);
        char[] allocCharBuffer = this._bufferRecycler.allocCharBuffer(CharBufferType.CONCAT_BUFFER);
        this._concatCBuffer = allocCharBuffer;
        return allocCharBuffer;
    }

    public char[] allocNameCopyBuffer(int i) {
        _verifyAlloc(this._nameCopyBuffer);
        char[] allocCharBuffer = this._bufferRecycler.allocCharBuffer(CharBufferType.NAME_COPY_BUFFER, i);
        this._nameCopyBuffer = allocCharBuffer;
        return allocCharBuffer;
    }

    public void releaseReadIOBuffer(byte[] bArr) {
        if (bArr != null) {
            _verifyRelease(bArr, this._readIOBuffer);
            this._readIOBuffer = null;
            this._bufferRecycler.releaseByteBuffer(ByteBufferType.READ_IO_BUFFER, bArr);
        }
    }

    public void releaseWriteEncodingBuffer(byte[] bArr) {
        if (bArr != null) {
            _verifyRelease(bArr, this._writeEncodingBuffer);
            this._writeEncodingBuffer = null;
            this._bufferRecycler.releaseByteBuffer(ByteBufferType.WRITE_ENCODING_BUFFER, bArr);
        }
    }

    public void releaseBase64Buffer(byte[] bArr) {
        if (bArr != null) {
            _verifyRelease(bArr, this._base64Buffer);
            this._base64Buffer = null;
            this._bufferRecycler.releaseByteBuffer(ByteBufferType.BASE64_CODEC_BUFFER, bArr);
        }
    }

    public void releaseTokenBuffer(char[] cArr) {
        if (cArr != null) {
            _verifyRelease(cArr, this._tokenCBuffer);
            this._tokenCBuffer = null;
            this._bufferRecycler.releaseCharBuffer(CharBufferType.TOKEN_BUFFER, cArr);
        }
    }

    public void releaseConcatBuffer(char[] cArr) {
        if (cArr != null) {
            _verifyRelease(cArr, this._concatCBuffer);
            this._concatCBuffer = null;
            this._bufferRecycler.releaseCharBuffer(CharBufferType.CONCAT_BUFFER, cArr);
        }
    }

    public void releaseNameCopyBuffer(char[] cArr) {
        if (cArr != null) {
            _verifyRelease(cArr, this._nameCopyBuffer);
            this._nameCopyBuffer = null;
            this._bufferRecycler.releaseCharBuffer(CharBufferType.NAME_COPY_BUFFER, cArr);
        }
    }

    private final void _verifyAlloc(Object obj) {
        if (obj != null) {
            throw new IllegalStateException("Trying to call same allocXxx() method second time");
        }
    }

    private final void _verifyRelease(Object obj, Object obj2) {
        if (obj != obj2) {
            throw new IllegalArgumentException("Trying to release buffer not owned by the context");
        }
    }
}