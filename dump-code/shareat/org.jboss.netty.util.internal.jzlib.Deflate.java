package org.jboss.netty.util.internal.jzlib;

import android.support.v4.internal.view.SupportMenu;
import android.support.v4.view.MotionEventCompat;

final class Deflate {
    private static final int BUSY_STATE = 113;
    private static final int BlockDone = 1;
    private static final int Buf_size = 16;
    private static final int DYN_TREES = 2;
    private static final int END_BLOCK = 256;
    private static final int FAST = 1;
    private static final int FINISH_STATE = 666;
    private static final int FinishDone = 3;
    private static final int FinishStarted = 2;
    private static final int INIT_STATE = 42;
    private static final int MAX_MATCH = 258;
    private static final int MIN_LOOKAHEAD = 262;
    private static final int MIN_MATCH = 3;
    private static final int NeedMore = 0;
    private static final int REPZ_11_138 = 18;
    private static final int REPZ_3_10 = 17;
    private static final int REP_3_6 = 16;
    private static final int SLOW = 2;
    private static final int STATIC_TREES = 1;
    private static final int STORED = 0;
    private static final int STORED_BLOCK = 0;
    private static final int Z_ASCII = 1;
    private static final int Z_BINARY = 0;
    private static final int Z_UNKNOWN = 2;
    private static final Config[] config_table = new Config[10];
    private static final String[] z_errmsg = {"need dictionary", "stream end", "", "file error", "stream error", "data error", "insufficient memory", "buffer error", "incompatible version", ""};
    short bi_buf;
    int bi_valid;
    final short[] bl_count = new short[16];
    final Tree bl_desc = new Tree();
    final short[] bl_tree = new short[78];
    int block_start;
    int d_buf;
    final Tree d_desc = new Tree();
    byte data_type;
    final byte[] depth = new byte[573];
    final short[] dyn_dtree = new short[122];
    final short[] dyn_ltree = new short[1146];
    int good_match;
    private int gzipUncompressedBytes;
    int hash_bits;
    int hash_mask;
    int hash_shift;
    int hash_size;
    short[] head;
    final int[] heap = new int[573];
    int heap_len;
    int heap_max;
    int ins_h;
    int l_buf;
    final Tree l_desc = new Tree();
    int last_eob_len;
    int last_flush;
    int last_lit;
    int level;
    int lit_bufsize;
    int lookahead;
    int match_available;
    int match_length;
    int match_start;
    int matches;
    int max_chain_length;
    int max_lazy_match;
    int nice_match;
    int opt_len;
    int pending;
    byte[] pending_buf;
    int pending_buf_size;
    int pending_out;
    short[] prev;
    int prev_length;
    int prev_match;
    int static_len;
    int status;
    int strategy;
    ZStream strm;
    int strstart;
    int w_bits;
    int w_mask;
    int w_size;
    byte[] window;
    int window_size;
    WrapperType wrapperType;
    private boolean wroteTrailer;

    private static final class Config {
        final int func;
        final int good_length;
        final int max_chain;
        final int max_lazy;
        final int nice_length;

        Config(int good_length2, int max_lazy2, int nice_length2, int max_chain2, int func2) {
            this.good_length = good_length2;
            this.max_lazy = max_lazy2;
            this.nice_length = nice_length2;
            this.max_chain = max_chain2;
            this.func = func2;
        }
    }

    static {
        config_table[0] = new Config(0, 0, 0, 0, 0);
        config_table[1] = new Config(4, 4, 8, 4, 1);
        config_table[2] = new Config(4, 5, 16, 8, 1);
        config_table[3] = new Config(4, 6, 32, 32, 1);
        config_table[4] = new Config(4, 4, 16, 16, 2);
        config_table[5] = new Config(8, 16, 32, 32, 2);
        config_table[6] = new Config(8, 16, 128, 128, 2);
        config_table[7] = new Config(8, 32, 128, 256, 2);
        config_table[8] = new Config(32, 128, MAX_MATCH, 1024, 2);
        config_table[9] = new Config(32, MAX_MATCH, MAX_MATCH, 4096, 2);
    }

    Deflate() {
    }

    private void lm_init() {
        this.window_size = this.w_size * 2;
        this.max_lazy_match = config_table[this.level].max_lazy;
        this.good_match = config_table[this.level].good_length;
        this.nice_match = config_table[this.level].nice_length;
        this.max_chain_length = config_table[this.level].max_chain;
        this.strstart = 0;
        this.block_start = 0;
        this.lookahead = 0;
        this.prev_length = 2;
        this.match_length = 2;
        this.match_available = 0;
        this.ins_h = 0;
    }

    private void tr_init() {
        this.l_desc.dyn_tree = this.dyn_ltree;
        this.l_desc.stat_desc = StaticTree.static_l_desc;
        this.d_desc.dyn_tree = this.dyn_dtree;
        this.d_desc.stat_desc = StaticTree.static_d_desc;
        this.bl_desc.dyn_tree = this.bl_tree;
        this.bl_desc.stat_desc = StaticTree.static_bl_desc;
        this.bi_buf = 0;
        this.bi_valid = 0;
        this.last_eob_len = 8;
        init_block();
    }

    private void init_block() {
        for (int i = 0; i < 286; i++) {
            this.dyn_ltree[i * 2] = 0;
        }
        for (int i2 = 0; i2 < 30; i2++) {
            this.dyn_dtree[i2 * 2] = 0;
        }
        for (int i3 = 0; i3 < 19; i3++) {
            this.bl_tree[i3 * 2] = 0;
        }
        this.dyn_ltree[512] = 1;
        this.static_len = 0;
        this.opt_len = 0;
        this.matches = 0;
        this.last_lit = 0;
    }

    /* access modifiers changed from: 0000 */
    public void pqdownheap(short[] tree, int k) {
        int v = this.heap[k];
        int j = k << 1;
        while (j <= this.heap_len) {
            if (j < this.heap_len && smaller(tree, this.heap[j + 1], this.heap[j], this.depth)) {
                j++;
            }
            if (smaller(tree, v, this.heap[j], this.depth)) {
                break;
            }
            this.heap[k] = this.heap[j];
            k = j;
            j <<= 1;
        }
        this.heap[k] = v;
    }

    private static boolean smaller(short[] tree, int n, int m, byte[] depth2) {
        short tn2 = tree[n * 2];
        short tm2 = tree[m * 2];
        return tn2 < tm2 || (tn2 == tm2 && depth2[n] <= depth2[m]);
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=short, code=int, for r5v0, types: [short] */
    /* JADX WARNING: Incorrect type for immutable var: ssa=short, code=int, for r5v2, types: [short] */
    private void scan_tree(short[] tree, int max_code) {
        int prevlen = -1;
        int nextlen = tree[1];
        int count = 0;
        int max_count = 7;
        int min_count = 4;
        if (nextlen == 0) {
            max_count = 138;
            min_count = 3;
        }
        tree[((max_code + 1) * 2) + 1] = -1;
        for (int n = 0; n <= max_code; n++) {
            int curlen = nextlen;
            nextlen = tree[((n + 1) * 2) + 1];
            count++;
            if (count >= max_count || curlen != nextlen) {
                if (count < min_count) {
                    short[] sArr = this.bl_tree;
                    int i = curlen * 2;
                    sArr[i] = (short) (sArr[i] + count);
                } else if (curlen != 0) {
                    if (curlen != prevlen) {
                        short[] sArr2 = this.bl_tree;
                        int i2 = curlen * 2;
                        sArr2[i2] = (short) (sArr2[i2] + 1);
                    }
                    short[] sArr3 = this.bl_tree;
                    sArr3[32] = (short) (sArr3[32] + 1);
                } else if (count <= 10) {
                    short[] sArr4 = this.bl_tree;
                    sArr4[34] = (short) (sArr4[34] + 1);
                } else {
                    short[] sArr5 = this.bl_tree;
                    sArr5[36] = (short) (sArr5[36] + 1);
                }
                count = 0;
                prevlen = curlen;
                if (nextlen == 0) {
                    max_count = 138;
                    min_count = 3;
                } else if (curlen == nextlen) {
                    max_count = 6;
                    min_count = 3;
                } else {
                    max_count = 7;
                    min_count = 4;
                }
            }
        }
    }

    private int build_bl_tree() {
        scan_tree(this.dyn_ltree, this.l_desc.max_code);
        scan_tree(this.dyn_dtree, this.d_desc.max_code);
        this.bl_desc.build_tree(this);
        int max_blindex = 18;
        while (max_blindex >= 3 && this.bl_tree[(Tree.bl_order[max_blindex] * 2) + 1] == 0) {
            max_blindex--;
        }
        this.opt_len += ((max_blindex + 1) * 3) + 5 + 5 + 4;
        return max_blindex;
    }

    private void send_all_trees(int lcodes, int dcodes, int blcodes) {
        send_bits(lcodes - 257, 5);
        send_bits(dcodes - 1, 5);
        send_bits(blcodes - 4, 4);
        for (int rank = 0; rank < blcodes; rank++) {
            send_bits(this.bl_tree[(Tree.bl_order[rank] * 2) + 1], 3);
        }
        send_tree(this.dyn_ltree, lcodes - 1);
        send_tree(this.dyn_dtree, dcodes - 1);
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=short, code=int, for r5v0, types: [short] */
    /* JADX WARNING: Incorrect type for immutable var: ssa=short, code=int, for r5v2, types: [short] */
    private void send_tree(short[] tree, int max_code) {
        int prevlen = -1;
        int nextlen = tree[1];
        int count = 0;
        int max_count = 7;
        int min_count = 4;
        if (nextlen == 0) {
            max_count = 138;
            min_count = 3;
        }
        for (int n = 0; n <= max_code; n++) {
            int curlen = nextlen;
            nextlen = tree[((n + 1) * 2) + 1];
            count++;
            if (count >= max_count || curlen != nextlen) {
                if (count < min_count) {
                    do {
                        send_code(curlen, this.bl_tree);
                        count--;
                    } while (count != 0);
                } else if (curlen != 0) {
                    if (curlen != prevlen) {
                        send_code(curlen, this.bl_tree);
                        count--;
                    }
                    send_code(16, this.bl_tree);
                    send_bits(count - 3, 2);
                } else if (count <= 10) {
                    send_code(17, this.bl_tree);
                    send_bits(count - 3, 3);
                } else {
                    send_code(18, this.bl_tree);
                    send_bits(count - 11, 7);
                }
                count = 0;
                prevlen = curlen;
                if (nextlen == 0) {
                    max_count = 138;
                    min_count = 3;
                } else if (curlen == nextlen) {
                    max_count = 6;
                    min_count = 3;
                } else {
                    max_count = 7;
                    min_count = 4;
                }
            }
        }
    }

    private void put_byte(byte[] p, int start, int len) {
        System.arraycopy(p, start, this.pending_buf, this.pending, len);
        this.pending += len;
    }

    private void put_byte(byte c) {
        byte[] bArr = this.pending_buf;
        int i = this.pending;
        this.pending = i + 1;
        bArr[i] = c;
    }

    private void put_short(int w) {
        put_byte((byte) w);
        put_byte((byte) (w >>> 8));
    }

    private void putShortMSB(int b) {
        put_byte((byte) (b >> 8));
        put_byte((byte) b);
    }

    private void send_code(int c, short[] tree) {
        int c2 = c * 2;
        send_bits(tree[c2] & 65535, tree[c2 + 1] & 65535);
    }

    private void send_bits(int value, int length) {
        int len = length;
        if (this.bi_valid > 16 - len) {
            int val = value;
            this.bi_buf = (short) (this.bi_buf | ((val << this.bi_valid) & 65535));
            put_short(this.bi_buf);
            this.bi_buf = (short) (val >>> (16 - this.bi_valid));
            this.bi_valid += len - 16;
            return;
        }
        this.bi_buf = (short) (this.bi_buf | ((value << this.bi_valid) & 65535));
        this.bi_valid += len;
    }

    private void _tr_align() {
        send_bits(2, 3);
        send_code(256, StaticTree.static_ltree);
        bi_flush();
        if (((this.last_eob_len + 1) + 10) - this.bi_valid < 9) {
            send_bits(2, 3);
            send_code(256, StaticTree.static_ltree);
            bi_flush();
        }
        this.last_eob_len = 7;
    }

    private boolean _tr_tally(int dist, int lc) {
        this.pending_buf[this.d_buf + (this.last_lit * 2)] = (byte) (dist >>> 8);
        this.pending_buf[this.d_buf + (this.last_lit * 2) + 1] = (byte) dist;
        this.pending_buf[this.l_buf + this.last_lit] = (byte) lc;
        this.last_lit++;
        if (dist == 0) {
            short[] sArr = this.dyn_ltree;
            int i = lc * 2;
            sArr[i] = (short) (sArr[i] + 1);
        } else {
            this.matches++;
            short[] sArr2 = this.dyn_ltree;
            int i2 = (Tree._length_code[lc] + 256 + 1) * 2;
            sArr2[i2] = (short) (sArr2[i2] + 1);
            short[] sArr3 = this.dyn_dtree;
            int d_code = Tree.d_code(dist - 1) * 2;
            sArr3[d_code] = (short) (sArr3[d_code] + 1);
        }
        if ((this.last_lit & 8191) == 0 && this.level > 2) {
            int out_length = this.last_lit * 8;
            int in_length = this.strstart - this.block_start;
            for (int dcode = 0; dcode < 30; dcode++) {
                out_length = (int) (((long) out_length) + (((long) this.dyn_dtree[dcode * 2]) * (5 + ((long) Tree.extra_dbits[dcode]))));
            }
            int out_length2 = out_length >>> 3;
            if (this.matches < this.last_lit / 2 && out_length2 < in_length / 2) {
                return true;
            }
        }
        if (this.last_lit != this.lit_bufsize - 1) {
            return false;
        }
        return true;
    }

    private void compress_block(short[] ltree, short[] dtree) {
        int lx = 0;
        if (this.last_lit != 0) {
            do {
                int dist = ((this.pending_buf[this.d_buf + (lx * 2)] << 8) & MotionEventCompat.ACTION_POINTER_INDEX_MASK) | (this.pending_buf[this.d_buf + (lx * 2) + 1] & 255);
                int lc = this.pending_buf[this.l_buf + lx] & 255;
                lx++;
                if (dist == 0) {
                    send_code(lc, ltree);
                } else {
                    byte code = Tree._length_code[lc];
                    send_code(code + 256 + 1, ltree);
                    int extra = Tree.extra_lbits[code];
                    if (extra != 0) {
                        send_bits(lc - Tree.base_length[code], extra);
                    }
                    int dist2 = dist - 1;
                    int code2 = Tree.d_code(dist2);
                    send_code(code2, dtree);
                    int extra2 = Tree.extra_dbits[code2];
                    if (extra2 != 0) {
                        send_bits(dist2 - Tree.base_dist[code2], extra2);
                    }
                }
            } while (lx < this.last_lit);
        }
        send_code(256, ltree);
        this.last_eob_len = ltree[513];
    }

    private void set_data_type() {
        int n = 0;
        int ascii_freq = 0;
        int bin_freq = 0;
        while (n < 7) {
            bin_freq += this.dyn_ltree[n * 2];
            n++;
        }
        while (n < 128) {
            ascii_freq += this.dyn_ltree[n * 2];
            n++;
        }
        while (n < 256) {
            bin_freq += this.dyn_ltree[n * 2];
            n++;
        }
        this.data_type = (byte) (bin_freq > (ascii_freq >>> 2) ? 0 : 1);
    }

    private void bi_flush() {
        if (this.bi_valid == 16) {
            put_short(this.bi_buf);
            this.bi_buf = 0;
            this.bi_valid = 0;
        } else if (this.bi_valid >= 8) {
            put_byte((byte) this.bi_buf);
            this.bi_buf = (short) (this.bi_buf >>> 8);
            this.bi_valid -= 8;
        }
    }

    private void bi_windup() {
        if (this.bi_valid > 8) {
            put_short(this.bi_buf);
        } else if (this.bi_valid > 0) {
            put_byte((byte) this.bi_buf);
        }
        this.bi_buf = 0;
        this.bi_valid = 0;
    }

    private void copy_block(int buf, int len, boolean header) {
        bi_windup();
        this.last_eob_len = 8;
        if (header) {
            put_short((short) len);
            put_short((short) (len ^ -1));
        }
        put_byte(this.window, buf, len);
    }

    private void flush_block_only(boolean eof) {
        _tr_flush_block(this.block_start >= 0 ? this.block_start : -1, this.strstart - this.block_start, eof);
        this.block_start = this.strstart;
        this.strm.flush_pending();
    }

    private int deflate_stored(int flush) {
        boolean z;
        int i = 1;
        int max_block_size = SupportMenu.USER_MASK;
        if (65535 > this.pending_buf_size - 5) {
            max_block_size = this.pending_buf_size - 5;
        }
        while (true) {
            if (this.lookahead <= 1) {
                fill_window();
                if (this.lookahead == 0 && flush == 0) {
                    return 0;
                }
                if (this.lookahead == 0) {
                    if (flush == 4) {
                        z = true;
                    } else {
                        z = false;
                    }
                    flush_block_only(z);
                    if (this.strm.avail_out != 0) {
                        if (flush == 4) {
                            i = 3;
                        }
                        return i;
                    } else if (flush == 4) {
                        return 2;
                    } else {
                        return 0;
                    }
                }
            }
            this.strstart += this.lookahead;
            this.lookahead = 0;
            int max_start = this.block_start + max_block_size;
            if (this.strstart == 0 || this.strstart >= max_start) {
                this.lookahead = this.strstart - max_start;
                this.strstart = max_start;
                flush_block_only(false);
                if (this.strm.avail_out == 0) {
                    return 0;
                }
            }
            if (this.strstart - this.block_start >= this.w_size - 262) {
                flush_block_only(false);
                if (this.strm.avail_out == 0) {
                    return 0;
                }
            }
        }
    }

    private void _tr_stored_block(int buf, int stored_len, boolean eof) {
        send_bits((eof ? 1 : 0) + 0, 3);
        copy_block(buf, stored_len, true);
    }

    private void _tr_flush_block(int buf, int stored_len, boolean eof) {
        int static_lenb;
        int opt_lenb;
        int i = 1;
        int max_blindex = 0;
        if (this.level > 0) {
            if (this.data_type == 2) {
                set_data_type();
            }
            this.l_desc.build_tree(this);
            this.d_desc.build_tree(this);
            max_blindex = build_bl_tree();
            opt_lenb = ((this.opt_len + 3) + 7) >>> 3;
            static_lenb = ((this.static_len + 3) + 7) >>> 3;
            if (static_lenb <= opt_lenb) {
                opt_lenb = static_lenb;
            }
        } else {
            static_lenb = stored_len + 5;
            opt_lenb = static_lenb;
        }
        if (stored_len + 4 <= opt_lenb && buf != -1) {
            _tr_stored_block(buf, stored_len, eof);
        } else if (static_lenb == opt_lenb) {
            if (!eof) {
                i = 0;
            }
            send_bits(i + 2, 3);
            compress_block(StaticTree.static_ltree, StaticTree.static_dtree);
        } else {
            if (!eof) {
                i = 0;
            }
            send_bits(i + 4, 3);
            send_all_trees(this.l_desc.max_code + 1, this.d_desc.max_code + 1, max_blindex + 1);
            compress_block(this.dyn_ltree, this.dyn_dtree);
        }
        init_block();
        if (eof) {
            bi_windup();
        }
    }

    private void fill_window() {
        short s;
        do {
            int more = (this.window_size - this.lookahead) - this.strstart;
            if (more == 0 && this.strstart == 0 && this.lookahead == 0) {
                more = this.w_size;
            } else if (more == -1) {
                more--;
            } else if (this.strstart >= (this.w_size + this.w_size) - 262) {
                System.arraycopy(this.window, this.w_size, this.window, 0, this.w_size);
                this.match_start -= this.w_size;
                this.strstart -= this.w_size;
                this.block_start -= this.w_size;
                int n = this.hash_size;
                int p = n;
                do {
                    p--;
                    int m = this.head[p] & SupportMenu.USER_MASK;
                    this.head[p] = m >= this.w_size ? (short) (m - this.w_size) : 0;
                    n--;
                } while (n != 0);
                int n2 = this.w_size;
                int p2 = n2;
                do {
                    p2--;
                    int m2 = this.prev[p2] & SupportMenu.USER_MASK;
                    short[] sArr = this.prev;
                    if (m2 >= this.w_size) {
                        s = (short) (m2 - this.w_size);
                    } else {
                        s = 0;
                    }
                    sArr[p2] = s;
                    n2--;
                } while (n2 != 0);
                more += this.w_size;
            }
            if (this.strm.avail_in != 0) {
                this.lookahead += this.strm.read_buf(this.window, this.strstart + this.lookahead, more);
                if (this.lookahead >= 3) {
                    this.ins_h = this.window[this.strstart] & 255;
                    this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[this.strstart + 1] & 255)) & this.hash_mask;
                }
                if (this.lookahead >= MIN_LOOKAHEAD) {
                    return;
                }
            } else {
                return;
            }
        } while (this.strm.avail_in != 0);
    }

    private int deflate_fast(int flush) {
        boolean bflush;
        int i;
        boolean z;
        int i2 = 1;
        int hash_head = 0;
        while (true) {
            if (this.lookahead < MIN_LOOKAHEAD) {
                fill_window();
                if (this.lookahead < MIN_LOOKAHEAD && flush == 0) {
                    return 0;
                }
                if (this.lookahead == 0) {
                    if (flush == 4) {
                        z = true;
                    } else {
                        z = false;
                    }
                    flush_block_only(z);
                    if (this.strm.avail_out != 0) {
                        if (flush == 4) {
                            i2 = 3;
                        }
                        return i2;
                    } else if (flush == 4) {
                        return 2;
                    } else {
                        return 0;
                    }
                }
            }
            if (this.lookahead >= 3) {
                this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[(this.strstart + 3) - 1] & 255)) & this.hash_mask;
                hash_head = this.head[this.ins_h] & SupportMenu.USER_MASK;
                this.prev[this.strstart & this.w_mask] = this.head[this.ins_h];
                this.head[this.ins_h] = (short) this.strstart;
            }
            if (!(((long) hash_head) == 0 || ((this.strstart - hash_head) & SupportMenu.USER_MASK) > this.w_size - 262 || this.strategy == 2)) {
                this.match_length = longest_match(hash_head);
            }
            if (this.match_length >= 3) {
                bflush = _tr_tally(this.strstart - this.match_start, this.match_length - 3);
                this.lookahead -= this.match_length;
                if (this.match_length > this.max_lazy_match || this.lookahead < 3) {
                    this.strstart += this.match_length;
                    this.match_length = 0;
                    this.ins_h = this.window[this.strstart] & 255;
                    this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[this.strstart + 1] & 255)) & this.hash_mask;
                } else {
                    this.match_length--;
                    do {
                        this.strstart++;
                        this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[(this.strstart + 3) - 1] & 255)) & this.hash_mask;
                        hash_head = this.head[this.ins_h] & SupportMenu.USER_MASK;
                        this.prev[this.strstart & this.w_mask] = this.head[this.ins_h];
                        this.head[this.ins_h] = (short) this.strstart;
                        i = this.match_length - 1;
                        this.match_length = i;
                    } while (i != 0);
                    this.strstart++;
                }
            } else {
                bflush = _tr_tally(0, this.window[this.strstart] & 255);
                this.lookahead--;
                this.strstart++;
            }
            if (bflush) {
                flush_block_only(false);
                if (this.strm.avail_out == 0) {
                    return 0;
                }
            }
        }
    }

    private int deflate_slow(int flush) {
        int i;
        boolean z;
        int i2 = 1;
        int hash_head = 0;
        while (true) {
            if (this.lookahead < MIN_LOOKAHEAD) {
                fill_window();
                if (this.lookahead < MIN_LOOKAHEAD && flush == 0) {
                    return 0;
                }
                if (this.lookahead == 0) {
                    if (this.match_available != 0) {
                        _tr_tally(0, this.window[this.strstart - 1] & 255);
                        this.match_available = 0;
                    }
                    if (flush == 4) {
                        z = true;
                    } else {
                        z = false;
                    }
                    flush_block_only(z);
                    if (this.strm.avail_out != 0) {
                        if (flush == 4) {
                            i2 = 3;
                        }
                        return i2;
                    } else if (flush == 4) {
                        return 2;
                    } else {
                        return 0;
                    }
                }
            }
            if (this.lookahead >= 3) {
                this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[(this.strstart + 3) - 1] & 255)) & this.hash_mask;
                hash_head = this.head[this.ins_h] & SupportMenu.USER_MASK;
                this.prev[this.strstart & this.w_mask] = this.head[this.ins_h];
                this.head[this.ins_h] = (short) this.strstart;
            }
            this.prev_length = this.match_length;
            this.prev_match = this.match_start;
            this.match_length = 2;
            if (hash_head != 0 && this.prev_length < this.max_lazy_match && ((this.strstart - hash_head) & SupportMenu.USER_MASK) <= this.w_size - 262) {
                if (this.strategy != 2) {
                    this.match_length = longest_match(hash_head);
                }
                if (this.match_length <= 5 && (this.strategy == 1 || (this.match_length == 3 && this.strstart - this.match_start > 4096))) {
                    this.match_length = 2;
                }
            }
            if (this.prev_length >= 3 && this.match_length <= this.prev_length) {
                int max_insert = (this.strstart + this.lookahead) - 3;
                boolean bflush = _tr_tally((this.strstart - 1) - this.prev_match, this.prev_length - 3);
                this.lookahead -= this.prev_length - 1;
                this.prev_length -= 2;
                do {
                    int i3 = this.strstart + 1;
                    this.strstart = i3;
                    if (i3 <= max_insert) {
                        this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[(this.strstart + 3) - 1] & 255)) & this.hash_mask;
                        hash_head = this.head[this.ins_h] & SupportMenu.USER_MASK;
                        this.prev[this.strstart & this.w_mask] = this.head[this.ins_h];
                        this.head[this.ins_h] = (short) this.strstart;
                    }
                    i = this.prev_length - 1;
                    this.prev_length = i;
                } while (i != 0);
                this.match_available = 0;
                this.match_length = 2;
                this.strstart++;
                if (bflush) {
                    flush_block_only(false);
                    if (this.strm.avail_out == 0) {
                        return 0;
                    }
                } else {
                    continue;
                }
            } else if (this.match_available != 0) {
                if (_tr_tally(0, this.window[this.strstart - 1] & 255)) {
                    flush_block_only(false);
                }
                this.strstart++;
                this.lookahead--;
                if (this.strm.avail_out == 0) {
                    return 0;
                }
            } else {
                this.match_available = 1;
                this.strstart++;
                this.lookahead--;
            }
        }
    }

    private int longest_match(int cur_match) {
        int chain_length = this.max_chain_length;
        int scan = this.strstart;
        int best_len = this.prev_length;
        int limit = this.strstart > this.w_size + -262 ? this.strstart - (this.w_size - 262) : 0;
        int nice_match2 = this.nice_match;
        int wmask = this.w_mask;
        int strend = this.strstart + MAX_MATCH;
        byte scan_end1 = this.window[(scan + best_len) - 1];
        byte scan_end = this.window[scan + best_len];
        if (this.prev_length >= this.good_match) {
            chain_length >>= 2;
        }
        if (nice_match2 > this.lookahead) {
            nice_match2 = this.lookahead;
        }
        do {
            int match = cur_match;
            if (this.window[match + best_len] == scan_end && this.window[(match + best_len) - 1] == scan_end1 && this.window[match] == this.window[scan]) {
                int match2 = match + 1;
                if (this.window[match2] == this.window[scan + 1]) {
                    int scan2 = scan + 2;
                    int match3 = match2 + 1;
                    do {
                        scan2++;
                        int match4 = match3 + 1;
                        if (this.window[scan2] != this.window[match4]) {
                            break;
                        }
                        scan2++;
                        int match5 = match4 + 1;
                        if (this.window[scan2] != this.window[match5]) {
                            break;
                        }
                        scan2++;
                        int match6 = match5 + 1;
                        if (this.window[scan2] != this.window[match6]) {
                            break;
                        }
                        scan2++;
                        int match7 = match6 + 1;
                        if (this.window[scan2] != this.window[match7]) {
                            break;
                        }
                        scan2++;
                        int match8 = match7 + 1;
                        if (this.window[scan2] != this.window[match8]) {
                            break;
                        }
                        scan2++;
                        int match9 = match8 + 1;
                        if (this.window[scan2] != this.window[match9]) {
                            break;
                        }
                        scan2++;
                        int match10 = match9 + 1;
                        if (this.window[scan2] != this.window[match10]) {
                            break;
                        }
                        scan2++;
                        match3 = match10 + 1;
                        if (this.window[scan2] != this.window[match3]) {
                            break;
                        }
                    } while (scan2 < strend);
                    int len = 258 - (strend - scan2);
                    scan = strend - 258;
                    if (len > best_len) {
                        this.match_start = cur_match;
                        best_len = len;
                        if (len >= nice_match2) {
                            break;
                        }
                        scan_end1 = this.window[(scan + best_len) - 1];
                        scan_end = this.window[scan + best_len];
                    }
                }
            }
            cur_match = this.prev[cur_match & wmask] & 65535;
            if (cur_match <= limit) {
                break;
            }
            chain_length--;
        } while (chain_length != 0);
        return best_len <= this.lookahead ? best_len : this.lookahead;
    }

    /* access modifiers changed from: 0000 */
    public int deflateInit(ZStream strm2, int level2, int bits, int memLevel, WrapperType wrapperType2) {
        return deflateInit2(strm2, level2, 8, bits, memLevel, 0, wrapperType2);
    }

    private int deflateInit2(ZStream strm2, int level2, int method, int windowBits, int memLevel, int strategy2, WrapperType wrapperType2) {
        if (wrapperType2 == WrapperType.ZLIB_OR_NONE) {
            throw new IllegalArgumentException("ZLIB_OR_NONE allowed only for inflate");
        }
        strm2.msg = null;
        if (level2 == -1) {
            level2 = 6;
        }
        if (windowBits < 0) {
            throw new IllegalArgumentException("windowBits: " + windowBits);
        } else if (memLevel < 1 || memLevel > 9 || method != 8 || windowBits < 9 || windowBits > 15 || level2 < 0 || level2 > 9 || strategy2 < 0 || strategy2 > 2) {
            return -2;
        } else {
            strm2.dstate = this;
            this.wrapperType = wrapperType2;
            this.w_bits = windowBits;
            this.w_size = 1 << this.w_bits;
            this.w_mask = this.w_size - 1;
            this.hash_bits = memLevel + 7;
            this.hash_size = 1 << this.hash_bits;
            this.hash_mask = this.hash_size - 1;
            this.hash_shift = ((this.hash_bits + 3) - 1) / 3;
            this.window = new byte[(this.w_size * 2)];
            this.prev = new short[this.w_size];
            this.head = new short[this.hash_size];
            this.lit_bufsize = 1 << (memLevel + 6);
            this.pending_buf = new byte[(this.lit_bufsize * 4)];
            this.pending_buf_size = this.lit_bufsize * 4;
            this.d_buf = this.lit_bufsize / 2;
            this.l_buf = this.lit_bufsize * 3;
            this.level = level2;
            this.strategy = strategy2;
            return deflateReset(strm2);
        }
    }

    private int deflateReset(ZStream strm2) {
        strm2.total_out = 0;
        strm2.total_in = 0;
        strm2.msg = null;
        this.pending = 0;
        this.pending_out = 0;
        this.wroteTrailer = false;
        this.status = this.wrapperType == WrapperType.NONE ? 113 : 42;
        strm2.adler = Adler32.adler32(0, null, 0, 0);
        strm2.crc32 = 0;
        this.gzipUncompressedBytes = 0;
        this.last_flush = 0;
        tr_init();
        lm_init();
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public int deflateEnd() {
        if (this.status != 42 && this.status != 113 && this.status != FINISH_STATE) {
            return -2;
        }
        this.pending_buf = null;
        this.head = null;
        this.prev = null;
        this.window = null;
        return this.status == 113 ? -3 : 0;
    }

    /* access modifiers changed from: 0000 */
    public int deflateParams(ZStream strm2, int _level, int _strategy) {
        int err = 0;
        if (_level == -1) {
            _level = 6;
        }
        if (_level < 0 || _level > 9 || _strategy < 0 || _strategy > 2) {
            return -2;
        }
        if (!(config_table[this.level].func == config_table[_level].func || strm2.total_in == 0)) {
            err = strm2.deflate(1);
        }
        if (this.level != _level) {
            this.level = _level;
            this.max_lazy_match = config_table[this.level].max_lazy;
            this.good_match = config_table[this.level].good_length;
            this.nice_match = config_table[this.level].nice_length;
            this.max_chain_length = config_table[this.level].max_chain;
        }
        this.strategy = _strategy;
        return err;
    }

    /* access modifiers changed from: 0000 */
    public int deflateSetDictionary(ZStream strm2, byte[] dictionary, int dictLength) {
        int length = dictLength;
        int index = 0;
        if (dictionary == null || this.status != 42) {
            return -2;
        }
        strm2.adler = Adler32.adler32(strm2.adler, dictionary, 0, dictLength);
        if (length < 3) {
            return 0;
        }
        if (length > this.w_size - 262) {
            length = this.w_size - 262;
            index = dictLength - length;
        }
        System.arraycopy(dictionary, index, this.window, 0, length);
        this.strstart = length;
        this.block_start = length;
        this.ins_h = this.window[0] & 255;
        this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[1] & 255)) & this.hash_mask;
        for (int n = 0; n <= length - 3; n++) {
            this.ins_h = ((this.ins_h << this.hash_shift) ^ (this.window[(n + 3) - 1] & 255)) & this.hash_mask;
            this.prev[this.w_mask & n] = this.head[this.ins_h];
            this.head[this.ins_h] = (short) n;
        }
        return 0;
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Removed duplicated region for block: B:72:0x013f A[Catch:{ all -> 0x01a5 }] */
    /* JADX WARNING: Removed duplicated region for block: B:76:0x0146 A[Catch:{ all -> 0x01a5 }] */
    public int deflate(ZStream strm2, int flush) {
        if (flush > 4 || flush < 0) {
            return -2;
        }
        if (strm2.next_out == null || ((strm2.next_in == null && strm2.avail_in != 0) || (this.status == FINISH_STATE && flush != 4))) {
            strm2.msg = z_errmsg[4];
            return -2;
        } else if (strm2.avail_out == 0) {
            strm2.msg = z_errmsg[7];
            return -5;
        } else {
            this.strm = strm2;
            int old_flush = this.last_flush;
            this.last_flush = flush;
            if (this.status == 42) {
                switch (this.wrapperType) {
                    case ZLIB:
                        int header = (((this.w_bits - 8) << 4) + 8) << 8;
                        int level_flags = ((this.level - 1) & 255) >> 1;
                        if (level_flags > 3) {
                            level_flags = 3;
                        }
                        int header2 = header | (level_flags << 6);
                        if (this.strstart != 0) {
                            header2 |= 32;
                        }
                        putShortMSB(header2 + (31 - (header2 % 31)));
                        if (this.strstart != 0) {
                            putShortMSB((int) (strm2.adler >>> 16));
                            putShortMSB((int) (strm2.adler & 65535));
                        }
                        strm2.adler = Adler32.adler32(0, null, 0, 0);
                        break;
                    case GZIP:
                        put_byte(31);
                        put_byte(-117);
                        put_byte(8);
                        put_byte(0);
                        put_byte(0);
                        put_byte(0);
                        put_byte(0);
                        put_byte(0);
                        switch (config_table[this.level].func) {
                            case 1:
                                put_byte(4);
                                break;
                            case 2:
                                put_byte(2);
                                break;
                            default:
                                put_byte(0);
                                break;
                        }
                        put_byte(-1);
                        strm2.crc32 = 0;
                        break;
                }
                this.status = 113;
            }
            if (this.pending != 0) {
                strm2.flush_pending();
                if (strm2.avail_out == 0) {
                    this.last_flush = -1;
                    return 0;
                }
            } else if (strm2.avail_in == 0 && flush <= old_flush && flush != 4) {
                strm2.msg = z_errmsg[7];
                return -5;
            }
            if (this.status != FINISH_STATE || strm2.avail_in == 0) {
                int old_next_in_index = strm2.next_in_index;
                try {
                    if (!(strm2.avail_in == 0 && this.lookahead == 0 && (flush == 0 || this.status == FINISH_STATE))) {
                        int bstate = -1;
                        switch (config_table[this.level].func) {
                            case 0:
                                bstate = deflate_stored(flush);
                            case 1:
                                bstate = deflate_fast(flush);
                                if (bstate == 2 || bstate == 3) {
                                    this.status = FINISH_STATE;
                                }
                                if (bstate != 0 || bstate == 2) {
                                    if (strm2.avail_out == 0) {
                                        this.last_flush = -1;
                                    }
                                    return 0;
                                } else if (bstate == 1) {
                                    if (flush == 1) {
                                        _tr_align();
                                    } else {
                                        _tr_stored_block(0, 0, false);
                                        if (flush == 3) {
                                            for (int i = 0; i < this.hash_size; i++) {
                                                this.head[i] = 0;
                                            }
                                        }
                                    }
                                    strm2.flush_pending();
                                    if (strm2.avail_out == 0) {
                                        this.last_flush = -1;
                                        this.gzipUncompressedBytes += strm2.next_in_index - old_next_in_index;
                                        return 0;
                                    }
                                }
                                break;
                            case 2:
                                bstate = deflate_slow(flush);
                                this.status = FINISH_STATE;
                                if (bstate != 0) {
                                    break;
                                }
                                if (strm2.avail_out == 0) {
                                }
                                return 0;
                        }
                        this.status = FINISH_STATE;
                        if (bstate != 0) {
                        }
                        if (strm2.avail_out == 0) {
                        }
                        return 0;
                    }
                    this.gzipUncompressedBytes += strm2.next_in_index - old_next_in_index;
                    if (flush != 4) {
                        return 0;
                    }
                    if (this.wrapperType == WrapperType.NONE || this.wroteTrailer) {
                        return 1;
                    }
                    switch (this.wrapperType) {
                        case ZLIB:
                            putShortMSB((int) (strm2.adler >>> 16));
                            putShortMSB((int) (strm2.adler & 65535));
                            break;
                        case GZIP:
                            put_byte((byte) (strm2.crc32 & 255));
                            put_byte((byte) ((strm2.crc32 >>> 8) & 255));
                            put_byte((byte) ((strm2.crc32 >>> 16) & 255));
                            put_byte((byte) ((strm2.crc32 >>> 24) & 255));
                            put_byte((byte) (this.gzipUncompressedBytes & 255));
                            put_byte((byte) ((this.gzipUncompressedBytes >>> 8) & 255));
                            put_byte((byte) ((this.gzipUncompressedBytes >>> 16) & 255));
                            put_byte((byte) ((this.gzipUncompressedBytes >>> 24) & 255));
                            break;
                    }
                    strm2.flush_pending();
                    this.wroteTrailer = true;
                    if (this.pending != 0) {
                        return 0;
                    }
                    return 1;
                } finally {
                    this.gzipUncompressedBytes += strm2.next_in_index - old_next_in_index;
                }
            } else {
                strm2.msg = z_errmsg[7];
                return -5;
            }
        }
    }
}