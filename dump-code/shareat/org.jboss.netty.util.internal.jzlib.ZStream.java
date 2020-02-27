package org.jboss.netty.util.internal.jzlib;

public final class ZStream {
    long adler;
    public int avail_in;
    public int avail_out;
    int crc32;
    Deflate dstate;
    Inflate istate;
    public String msg;
    public byte[] next_in;
    public int next_in_index;
    public byte[] next_out;
    public int next_out_index;
    public long total_in;
    public long total_out;

    public int inflateInit() {
        return inflateInit(15);
    }

    public int inflateInit(Enum<?> wrapperType) {
        return inflateInit(15, wrapperType);
    }

    public int inflateInit(int w) {
        return inflateInit(w, WrapperType.ZLIB);
    }

    public int inflateInit(int w, Enum wrapperType) {
        this.istate = new Inflate();
        return this.istate.inflateInit(this, w, (WrapperType) wrapperType);
    }

    public int inflate(int f) {
        if (this.istate == null) {
            return -2;
        }
        return this.istate.inflate(this, f);
    }

    public int inflateEnd() {
        if (this.istate == null) {
            return -2;
        }
        int inflateEnd = this.istate.inflateEnd(this);
        this.istate = null;
        return inflateEnd;
    }

    public int inflateSync() {
        if (this.istate == null) {
            return -2;
        }
        return this.istate.inflateSync(this);
    }

    public int inflateSetDictionary(byte[] dictionary, int dictLength) {
        if (this.istate == null) {
            return -2;
        }
        return Inflate.inflateSetDictionary(this, dictionary, dictLength);
    }

    public int deflateInit(int level) {
        return deflateInit(level, 15);
    }

    public int deflateInit(int level, Enum<?> wrapperType) {
        return deflateInit(level, 15, wrapperType);
    }

    public int deflateInit(int level, int bits) {
        return deflateInit(level, bits, WrapperType.ZLIB);
    }

    public int deflateInit(int level, int bits, Enum<?> wrapperType) {
        return deflateInit(level, bits, 8, wrapperType);
    }

    public int deflateInit(int level, int bits, int memLevel, Enum wrapperType) {
        this.dstate = new Deflate();
        return this.dstate.deflateInit(this, level, bits, memLevel, (WrapperType) wrapperType);
    }

    public int deflate(int flush) {
        if (this.dstate == null) {
            return -2;
        }
        return this.dstate.deflate(this, flush);
    }

    public int deflateEnd() {
        if (this.dstate == null) {
            return -2;
        }
        int deflateEnd = this.dstate.deflateEnd();
        this.dstate = null;
        return deflateEnd;
    }

    public int deflateParams(int level, int strategy) {
        if (this.dstate == null) {
            return -2;
        }
        return this.dstate.deflateParams(this, level, strategy);
    }

    public int deflateSetDictionary(byte[] dictionary, int dictLength) {
        if (this.dstate == null) {
            return -2;
        }
        return this.dstate.deflateSetDictionary(this, dictionary, dictLength);
    }

    /* access modifiers changed from: 0000 */
    public void flush_pending() {
        int len = this.dstate.pending;
        if (len > this.avail_out) {
            len = this.avail_out;
        }
        if (len != 0) {
            if (this.dstate.pending_buf.length <= this.dstate.pending_out || this.next_out.length <= this.next_out_index || this.dstate.pending_buf.length < this.dstate.pending_out + len || this.next_out.length < this.next_out_index + len) {
                System.out.println(this.dstate.pending_buf.length + ", " + this.dstate.pending_out + ", " + this.next_out.length + ", " + this.next_out_index + ", " + len);
                System.out.println("avail_out=" + this.avail_out);
            }
            System.arraycopy(this.dstate.pending_buf, this.dstate.pending_out, this.next_out, this.next_out_index, len);
            this.next_out_index += len;
            this.dstate.pending_out += len;
            this.total_out += (long) len;
            this.avail_out -= len;
            this.dstate.pending -= len;
            if (this.dstate.pending == 0) {
                this.dstate.pending_out = 0;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public int read_buf(byte[] buf, int start, int size) {
        int len = this.avail_in;
        if (len > size) {
            len = size;
        }
        if (len == 0) {
            return 0;
        }
        this.avail_in -= len;
        switch (this.dstate.wrapperType) {
            case ZLIB:
                this.adler = Adler32.adler32(this.adler, this.next_in, this.next_in_index, len);
                break;
            case GZIP:
                this.crc32 = CRC32.crc32(this.crc32, this.next_in, this.next_in_index, len);
                break;
        }
        System.arraycopy(this.next_in, this.next_in_index, buf, start, len);
        this.next_in_index += len;
        this.total_in += (long) len;
        return len;
    }

    public void free() {
        this.next_in = null;
        this.next_out = null;
        this.msg = null;
    }
}