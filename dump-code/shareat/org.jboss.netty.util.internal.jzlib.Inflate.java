package org.jboss.netty.util.internal.jzlib;

final class Inflate {
    private static final int BAD = 13;
    private static final int BLOCKS = 7;
    private static final int CHECK1 = 11;
    private static final int CHECK2 = 10;
    private static final int CHECK3 = 9;
    private static final int CHECK4 = 8;
    private static final int DICT0 = 6;
    private static final int DICT1 = 5;
    private static final int DICT2 = 4;
    private static final int DICT3 = 3;
    private static final int DICT4 = 2;
    private static final int DONE = 12;
    private static final int FLAG = 1;
    private static final int GZIP_CM = 16;
    private static final int GZIP_CRC32 = 24;
    private static final int GZIP_FCOMMENT = 22;
    private static final int GZIP_FEXTRA = 20;
    private static final int GZIP_FHCRC = 23;
    private static final int GZIP_FLG = 17;
    private static final int GZIP_FNAME = 21;
    private static final int GZIP_ID1 = 14;
    private static final int GZIP_ID2 = 15;
    private static final int GZIP_ISIZE = 25;
    private static final int GZIP_MTIME_XFL_OS = 18;
    private static final int GZIP_XLEN = 19;
    private static final int METHOD = 0;
    private static final byte[] mark = {0, 0, -1, -1};
    private InfBlocks blocks;
    private int gzipBytesToRead;
    private int gzipCRC32;
    private int gzipFlag;
    private int gzipISize;
    private int gzipUncompressedBytes;
    private int gzipXLen;
    private int marker;
    private int method;
    private int mode;
    private long need;
    private final long[] was = new long[1];
    private int wbits;
    private WrapperType wrapperType;

    Inflate() {
    }

    private int inflateReset(ZStream z) {
        if (z == null || z.istate == null) {
            return -2;
        }
        z.total_out = 0;
        z.total_in = 0;
        z.msg = null;
        switch (this.wrapperType) {
            case NONE:
                z.istate.mode = 7;
                break;
            case ZLIB:
            case ZLIB_OR_NONE:
                z.istate.mode = 0;
                break;
            case GZIP:
                z.istate.mode = 14;
                break;
        }
        z.istate.blocks.reset(z, null);
        this.gzipUncompressedBytes = 0;
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public int inflateEnd(ZStream z) {
        if (this.blocks != null) {
            this.blocks.free(z);
        }
        this.blocks = null;
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public int inflateInit(ZStream z, int w, WrapperType wrapperType2) {
        Inflate inflate = null;
        z.msg = null;
        this.blocks = null;
        this.wrapperType = wrapperType2;
        if (w < 0) {
            throw new IllegalArgumentException("w: " + w);
        } else if (w < 8 || w > 15) {
            inflateEnd(z);
            return -2;
        } else {
            this.wbits = w;
            Inflate inflate2 = z.istate;
            if (z.istate.wrapperType != WrapperType.NONE) {
                inflate = this;
            }
            inflate2.blocks = new InfBlocks(z, inflate, 1 << w);
            inflateReset(z);
            return 0;
        }
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Code restructure failed: missing block: B:122:0x0471, code lost:
        if (r12.gzipBytesToRead <= 0) goto L_0x0492;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:124:0x0475, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:125:0x0477, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r13.next_in_index++;
        r12.gzipBytesToRead--;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:126:0x0492, code lost:
        r13.istate.mode = 19;
        r12.gzipXLen = 0;
        r12.gzipBytesToRead = 2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:128:0x04a2, code lost:
        if ((r12.gzipFlag & 4) == 0) goto L_0x0506;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:130:0x04a6, code lost:
        if (r12.gzipBytesToRead <= 0) goto L_0x04d9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:132:0x04aa, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:133:0x04ac, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r12.gzipXLen;
        r5 = r13.next_in;
        r6 = r13.next_in_index;
        r13.next_in_index = r6 + 1;
        r12.gzipXLen = r4 | ((r5[r6] & 255) << ((1 - r12.gzipBytesToRead) * 8));
        r12.gzipBytesToRead--;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:134:0x04d9, code lost:
        r12.gzipBytesToRead = r12.gzipXLen;
        r13.istate.mode = 20;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:136:0x04e5, code lost:
        if (r12.gzipBytesToRead <= 0) goto L_0x050e;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:138:0x04e9, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:139:0x04eb, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r13.next_in_index++;
        r12.gzipBytesToRead--;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:140:0x0506, code lost:
        r13.istate.mode = 21;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:141:0x050e, code lost:
        r13.istate.mode = 21;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:143:0x0518, code lost:
        if ((r12.gzipFlag & 8) == 0) goto L_0x0538;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:145:0x051c, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:146:0x051e, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r13.next_in;
        r5 = r13.next_in_index;
        r13.next_in_index = r5 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:147:0x0536, code lost:
        if (r4[r5] != 0) goto L_0x051a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:148:0x0538, code lost:
        r13.istate.mode = 22;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:150:0x0542, code lost:
        if ((r12.gzipFlag & 16) == 0) goto L_0x0562;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:152:0x0546, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:153:0x0548, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r13.next_in;
        r5 = r13.next_in_index;
        r13.next_in_index = r5 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:154:0x0560, code lost:
        if (r4[r5] != 0) goto L_0x0544;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:155:0x0562, code lost:
        r12.gzipBytesToRead = 2;
        r13.istate.mode = 23;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:157:0x056f, code lost:
        if ((r12.gzipFlag & 2) == 0) goto L_0x0594;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:159:0x0573, code lost:
        if (r12.gzipBytesToRead <= 0) goto L_0x0594;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:161:0x0577, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:162:0x0579, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r13.next_in_index++;
        r12.gzipBytesToRead--;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:163:0x0594, code lost:
        r13.istate.mode = 7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:164:0x059b, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r12.gzipBytesToRead--;
        r4 = r13.istate;
        r5 = r4.gzipCRC32;
        r6 = r13.next_in;
        r7 = r13.next_in_index;
        r13.next_in_index = r7 + 1;
        r4.gzipCRC32 = r5 | ((r6[r7] & 255) << ((3 - r12.gzipBytesToRead) * 8));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:166:0x05cb, code lost:
        if (r12.gzipBytesToRead <= 0) goto L_0x05d3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:168:0x05cf, code lost:
        if (r13.avail_in != 0) goto L_0x059b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:170:0x05d9, code lost:
        if (r13.crc32 == r13.istate.gzipCRC32) goto L_0x05ed;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:171:0x05db, code lost:
        r13.istate.mode = 13;
        r13.msg = "incorrect CRC32 checksum";
        r13.istate.marker = 5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:172:0x05ed, code lost:
        r12.gzipBytesToRead = 4;
        r13.istate.mode = 25;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:174:0x05f8, code lost:
        if (r12.gzipBytesToRead <= 0) goto L_0x062d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:176:0x05fc, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:177:0x05fe, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r12.gzipBytesToRead--;
        r4 = r13.istate;
        r5 = r4.gzipISize;
        r6 = r13.next_in;
        r7 = r13.next_in_index;
        r13.next_in_index = r7 + 1;
        r4.gzipISize = r5 | ((r6[r7] & 255) << ((3 - r12.gzipBytesToRead) * 8));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:179:0x0633, code lost:
        if (r12.gzipUncompressedBytes == r13.istate.gzipISize) goto L_0x0647;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:180:0x0635, code lost:
        r13.istate.mode = 13;
        r13.msg = "incorrect ISIZE checksum";
        r13.istate.marker = 5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:181:0x0647, code lost:
        r13.istate.mode = 12;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:251:?, code lost:
        return 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:253:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:254:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:257:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:258:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:259:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:260:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:262:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:263:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:266:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:267:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:268:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:270:?, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:77:0x026e, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:78:0x0270, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r13.istate;
        r5 = r13.next_in;
        r6 = r13.next_in_index;
        r13.next_in_index = r6 + 1;
        r4.need = ((long) ((r5[r6] & 255) << 24)) & 4278190080L;
        r13.istate.mode = 9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:80:0x029f, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:81:0x02a1, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r13.istate;
        r6 = r4.need;
        r5 = r13.next_in;
        r8 = r13.next_in_index;
        r13.next_in_index = r8 + 1;
        r4.need = r6 + (((long) ((r5[r8] & 255) << 16)) & 16711680);
        r13.istate.mode = 10;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:83:0x02d1, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:84:0x02d3, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r13.istate;
        r6 = r4.need;
        r5 = r13.next_in;
        r8 = r13.next_in_index;
        r13.next_in_index = r8 + 1;
        r4.need = r6 + (((long) ((r5[r8] & 255) << 8)) & 65280);
        r13.istate.mode = 11;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:86:0x0303, code lost:
        if (r13.avail_in == 0) goto L_0x000b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:87:0x0305, code lost:
        r3 = r14;
        r13.avail_in--;
        r13.total_in++;
        r4 = r13.istate;
        r6 = r4.need;
        r5 = r13.next_in;
        r8 = r13.next_in_index;
        r13.next_in_index = r8 + 1;
        r4.need = r6 + (((long) r5[r8]) & 255);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:88:0x0335, code lost:
        if (((int) r13.istate.was[0]) == ((int) r13.istate.need)) goto L_0x0374;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:89:0x0337, code lost:
        r13.istate.mode = 13;
        r13.msg = "incorrect data check";
        r13.istate.marker = 5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:94:0x0374, code lost:
        r13.istate.mode = 12;
     */
    public int inflate(ZStream z, int f) {
        if (z == null || z.istate == null || z.next_in == null) {
            return -2;
        }
        int f2 = f == 4 ? -5 : 0;
        int r = -5;
        while (true) {
            switch (z.istate.mode) {
                case 0:
                    if (z.avail_in == 0) {
                        return r;
                    }
                    if (z.istate.wrapperType == WrapperType.ZLIB_OR_NONE) {
                        if ((z.next_in[z.next_in_index] & 15) != 8 || (z.next_in[z.next_in_index] >> 4) + 8 > z.istate.wbits) {
                            z.istate.wrapperType = WrapperType.NONE;
                            z.istate.mode = 7;
                            break;
                        } else {
                            z.istate.wrapperType = WrapperType.ZLIB;
                        }
                    }
                    r = f2;
                    z.avail_in--;
                    z.total_in++;
                    Inflate inflate = z.istate;
                    byte[] bArr = z.next_in;
                    int i = z.next_in_index;
                    z.next_in_index = i + 1;
                    byte b = bArr[i];
                    inflate.method = b;
                    if ((b & 15) != 8) {
                        z.istate.mode = 13;
                        z.msg = "unknown compression method";
                        z.istate.marker = 5;
                        break;
                    } else if ((z.istate.method >> 4) + 8 > z.istate.wbits) {
                        z.istate.mode = 13;
                        z.msg = "invalid window size";
                        z.istate.marker = 5;
                        break;
                    } else {
                        z.istate.mode = 1;
                    }
                    break;
                case 1:
                    if (z.avail_in != 0) {
                        r = f2;
                        z.avail_in--;
                        z.total_in++;
                        byte[] bArr2 = z.next_in;
                        int i2 = z.next_in_index;
                        z.next_in_index = i2 + 1;
                        int b2 = bArr2[i2] & 255;
                        if (((z.istate.method << 8) + b2) % 31 == 0) {
                            if ((b2 & 32) != 0) {
                                z.istate.mode = 2;
                                break;
                            } else {
                                z.istate.mode = 7;
                                break;
                            }
                        } else {
                            z.istate.mode = 13;
                            z.msg = "incorrect header check";
                            z.istate.marker = 5;
                            break;
                        }
                    } else {
                        return r;
                    }
                case 2:
                    break;
                case 3:
                    break;
                case 4:
                    break;
                case 5:
                    break;
                case 6:
                    z.istate.mode = 13;
                    z.msg = "need dictionary";
                    z.istate.marker = 0;
                    return -2;
                case 7:
                    int old_next_out_index = z.next_out_index;
                    try {
                        r = z.istate.blocks.proc(z, r);
                        if (r != -3) {
                            if (r == 0) {
                                r = f2;
                            }
                            if (r == 1) {
                                r = f2;
                                z.istate.blocks.reset(z, z.istate.was);
                                int decompressedBytes = z.next_out_index - old_next_out_index;
                                this.gzipUncompressedBytes += decompressedBytes;
                                z.crc32 = CRC32.crc32(z.crc32, z.next_out, old_next_out_index, decompressedBytes);
                                if (z.istate.wrapperType != WrapperType.NONE) {
                                    if (z.istate.wrapperType != WrapperType.ZLIB) {
                                        if (z.istate.wrapperType != WrapperType.GZIP) {
                                            z.istate.mode = 13;
                                            z.msg = "unexpected state";
                                            z.istate.marker = 0;
                                            break;
                                        } else {
                                            this.gzipCRC32 = 0;
                                            this.gzipISize = 0;
                                            this.gzipBytesToRead = 4;
                                            z.istate.mode = 24;
                                            break;
                                        }
                                    } else {
                                        z.istate.mode = 8;
                                        break;
                                    }
                                } else {
                                    z.istate.mode = 12;
                                    break;
                                }
                            } else {
                                int decompressedBytes2 = z.next_out_index - old_next_out_index;
                                this.gzipUncompressedBytes += decompressedBytes2;
                                z.crc32 = CRC32.crc32(z.crc32, z.next_out, old_next_out_index, decompressedBytes2);
                                return r;
                            }
                        } else {
                            z.istate.mode = 13;
                            z.istate.marker = 0;
                            break;
                        }
                    } finally {
                        int decompressedBytes3 = z.next_out_index - old_next_out_index;
                        this.gzipUncompressedBytes += decompressedBytes3;
                        z.crc32 = CRC32.crc32(z.crc32, z.next_out, old_next_out_index, decompressedBytes3);
                    }
                case 8:
                    break;
                case 9:
                    break;
                case 10:
                    break;
                case 11:
                    break;
                case 12:
                    break;
                case 13:
                    return -3;
                case 14:
                    if (z.avail_in == 0) {
                        return r;
                    }
                    r = f2;
                    z.avail_in--;
                    z.total_in++;
                    byte[] bArr3 = z.next_in;
                    int i3 = z.next_in_index;
                    z.next_in_index = i3 + 1;
                    if ((bArr3[i3] & 255) != 31) {
                        z.istate.mode = 13;
                        z.msg = "not a gzip stream";
                        z.istate.marker = 5;
                        break;
                    } else {
                        z.istate.mode = 15;
                    }
                case 15:
                    if (z.avail_in == 0) {
                        return r;
                    }
                    r = f2;
                    z.avail_in--;
                    z.total_in++;
                    byte[] bArr4 = z.next_in;
                    int i4 = z.next_in_index;
                    z.next_in_index = i4 + 1;
                    if ((bArr4[i4] & 255) != 139) {
                        z.istate.mode = 13;
                        z.msg = "not a gzip stream";
                        z.istate.marker = 5;
                        break;
                    } else {
                        z.istate.mode = 16;
                    }
                case 16:
                    if (z.avail_in == 0) {
                        return r;
                    }
                    r = f2;
                    z.avail_in--;
                    z.total_in++;
                    byte[] bArr5 = z.next_in;
                    int i5 = z.next_in_index;
                    z.next_in_index = i5 + 1;
                    if ((bArr5[i5] & 255) != 8) {
                        z.istate.mode = 13;
                        z.msg = "unknown compression method";
                        z.istate.marker = 5;
                        break;
                    } else {
                        z.istate.mode = 17;
                    }
                case 17:
                    if (z.avail_in != 0) {
                        r = f2;
                        z.avail_in--;
                        z.total_in++;
                        byte[] bArr6 = z.next_in;
                        int i6 = z.next_in_index;
                        z.next_in_index = i6 + 1;
                        this.gzipFlag = bArr6[i6] & 255;
                        if ((this.gzipFlag & 226) == 0) {
                            this.gzipBytesToRead = 6;
                            z.istate.mode = 18;
                            break;
                        } else {
                            z.istate.mode = 13;
                            z.msg = "unsupported flag";
                            z.istate.marker = 5;
                            break;
                        }
                    } else {
                        return r;
                    }
                case 18:
                    break;
                case 19:
                    break;
                case 20:
                    break;
                case 21:
                    break;
                case 22:
                    break;
                case 23:
                    break;
                case 24:
                    break;
                case 25:
                    break;
                default:
                    return -2;
            }
        }
        if (z.avail_in == 0) {
            return r;
        }
        r = f2;
        z.avail_in--;
        z.total_in++;
        Inflate inflate2 = z.istate;
        byte[] bArr7 = z.next_in;
        int i7 = z.next_in_index;
        z.next_in_index = i7 + 1;
        inflate2.need = ((long) ((bArr7[i7] & 255) << 24)) & 4278190080L;
        z.istate.mode = 3;
        if (z.avail_in == 0) {
            return r;
        }
        r = f2;
        z.avail_in--;
        z.total_in++;
        Inflate inflate3 = z.istate;
        long j = inflate3.need;
        byte[] bArr8 = z.next_in;
        int i8 = z.next_in_index;
        z.next_in_index = i8 + 1;
        inflate3.need = j + (((long) ((bArr8[i8] & 255) << 16)) & 16711680);
        z.istate.mode = 4;
        if (z.avail_in == 0) {
            return r;
        }
        r = f2;
        z.avail_in--;
        z.total_in++;
        Inflate inflate4 = z.istate;
        long j2 = inflate4.need;
        byte[] bArr9 = z.next_in;
        int i9 = z.next_in_index;
        z.next_in_index = i9 + 1;
        inflate4.need = j2 + (((long) ((bArr9[i9] & 255) << 8)) & 65280);
        z.istate.mode = 5;
        if (z.avail_in == 0) {
            return r;
        }
        z.avail_in--;
        z.total_in++;
        Inflate inflate5 = z.istate;
        long j3 = inflate5.need;
        byte[] bArr10 = z.next_in;
        int i10 = z.next_in_index;
        z.next_in_index = i10 + 1;
        inflate5.need = j3 + (((long) bArr10[i10]) & 255);
        z.adler = z.istate.need;
        z.istate.mode = 6;
        return 2;
    }

    static int inflateSetDictionary(ZStream z, byte[] dictionary, int dictLength) {
        int index = 0;
        int length = dictLength;
        if (z == null || z.istate == null || z.istate.mode != 6) {
            return -2;
        }
        if (Adler32.adler32(1, dictionary, 0, dictLength) != z.adler) {
            return -3;
        }
        z.adler = Adler32.adler32(0, null, 0, 0);
        if (length >= (1 << z.istate.wbits)) {
            length = (1 << z.istate.wbits) - 1;
            index = dictLength - length;
        }
        z.istate.blocks.set_dictionary(dictionary, index, length);
        z.istate.mode = 7;
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public int inflateSync(ZStream z) {
        if (z == null || z.istate == null) {
            return -2;
        }
        if (z.istate.mode != 13) {
            z.istate.mode = 13;
            z.istate.marker = 0;
        }
        int n = z.avail_in;
        if (n == 0) {
            return -5;
        }
        int p = z.next_in_index;
        int m = z.istate.marker;
        while (n != 0 && m < 4) {
            if (z.next_in[p] == mark[m]) {
                m++;
            } else if (z.next_in[p] != 0) {
                m = 0;
            } else {
                m = 4 - m;
            }
            p++;
            n--;
        }
        z.total_in += (long) (p - z.next_in_index);
        z.next_in_index = p;
        z.avail_in = n;
        z.istate.marker = m;
        if (m != 4) {
            return -3;
        }
        long r = z.total_in;
        long w = z.total_out;
        inflateReset(z);
        z.total_in = r;
        z.total_out = w;
        z.istate.mode = 7;
        return 0;
    }
}