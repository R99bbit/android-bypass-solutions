package com.squareup.okhttp.internal.spdy;

import com.facebook.share.internal.ShareConstants;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import com.kakao.util.helper.CommonProtocol;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import okio.Buffer;
import okio.BufferedSource;
import okio.ByteString;
import okio.Okio;
import okio.Source;

final class Hpack {
    /* access modifiers changed from: private */
    public static final Map<ByteString, Integer> NAME_TO_FIRST_INDEX = nameToFirstIndex();
    private static final int PREFIX_4_BITS = 15;
    private static final int PREFIX_5_BITS = 31;
    private static final int PREFIX_6_BITS = 63;
    private static final int PREFIX_7_BITS = 127;
    /* access modifiers changed from: private */
    public static final Header[] STATIC_HEADER_TABLE = {new Header(Header.TARGET_AUTHORITY, (String) ""), new Header(Header.TARGET_METHOD, (String) HttpRequest.METHOD_GET), new Header(Header.TARGET_METHOD, (String) HttpRequest.METHOD_POST), new Header(Header.TARGET_PATH, (String) "/"), new Header(Header.TARGET_PATH, (String) "/index.html"), new Header(Header.TARGET_SCHEME, (String) "http"), new Header(Header.TARGET_SCHEME, (String) CommonProtocol.URL_SCHEME), new Header(Header.RESPONSE_STATUS, (String) "200"), new Header(Header.RESPONSE_STATUS, (String) "204"), new Header(Header.RESPONSE_STATUS, (String) "206"), new Header(Header.RESPONSE_STATUS, (String) "304"), new Header(Header.RESPONSE_STATUS, (String) "400"), new Header(Header.RESPONSE_STATUS, (String) "404"), new Header(Header.RESPONSE_STATUS, (String) "500"), new Header((String) "accept-charset", (String) ""), new Header((String) "accept-encoding", (String) "gzip, deflate"), new Header((String) "accept-language", (String) ""), new Header((String) "accept-ranges", (String) ""), new Header((String) "accept", (String) ""), new Header((String) "access-control-allow-origin", (String) ""), new Header((String) "age", (String) ""), new Header((String) "allow", (String) ""), new Header((String) "authorization", (String) ""), new Header((String) "cache-control", (String) ""), new Header((String) "content-disposition", (String) ""), new Header((String) "content-encoding", (String) ""), new Header((String) "content-language", (String) ""), new Header((String) "content-length", (String) ""), new Header((String) "content-location", (String) ""), new Header((String) "content-range", (String) ""), new Header((String) "content-type", (String) ""), new Header((String) "cookie", (String) ""), new Header((String) "date", (String) ""), new Header((String) "etag", (String) ""), new Header((String) "expect", (String) ""), new Header((String) "expires", (String) ""), new Header((String) "from", (String) ""), new Header((String) "host", (String) ""), new Header((String) "if-match", (String) ""), new Header((String) "if-modified-since", (String) ""), new Header((String) "if-none-match", (String) ""), new Header((String) "if-range", (String) ""), new Header((String) "if-unmodified-since", (String) ""), new Header((String) "last-modified", (String) ""), new Header((String) ShareConstants.WEB_DIALOG_PARAM_LINK, (String) ""), new Header((String) Param.LOCATION, (String) ""), new Header((String) "max-forwards", (String) ""), new Header((String) "proxy-authenticate", (String) ""), new Header((String) "proxy-authorization", (String) ""), new Header((String) "range", (String) ""), new Header((String) "referer", (String) ""), new Header((String) "refresh", (String) ""), new Header((String) "retry-after", (String) ""), new Header((String) "server", (String) ""), new Header((String) "set-cookie", (String) ""), new Header((String) "strict-transport-security", (String) ""), new Header((String) "transfer-encoding", (String) ""), new Header((String) "user-agent", (String) ""), new Header((String) "vary", (String) ""), new Header((String) "via", (String) ""), new Header((String) "www-authenticate", (String) "")};

    static final class Reader {
        Header[] dynamicTable = new Header[8];
        int dynamicTableByteCount = 0;
        int headerCount = 0;
        private final List<Header> headerList = new ArrayList();
        private int headerTableSizeSetting;
        private int maxDynamicTableByteCount;
        int nextHeaderIndex = (this.dynamicTable.length - 1);
        private final BufferedSource source;

        Reader(int headerTableSizeSetting2, Source source2) {
            this.headerTableSizeSetting = headerTableSizeSetting2;
            this.maxDynamicTableByteCount = headerTableSizeSetting2;
            this.source = Okio.buffer(source2);
        }

        /* access modifiers changed from: 0000 */
        public int maxDynamicTableByteCount() {
            return this.maxDynamicTableByteCount;
        }

        /* access modifiers changed from: 0000 */
        public void headerTableSizeSetting(int headerTableSizeSetting2) {
            this.headerTableSizeSetting = headerTableSizeSetting2;
            this.maxDynamicTableByteCount = headerTableSizeSetting2;
            adjustDynamicTableByteCount();
        }

        private void adjustDynamicTableByteCount() {
            if (this.maxDynamicTableByteCount >= this.dynamicTableByteCount) {
                return;
            }
            if (this.maxDynamicTableByteCount == 0) {
                clearDynamicTable();
            } else {
                evictToRecoverBytes(this.dynamicTableByteCount - this.maxDynamicTableByteCount);
            }
        }

        private void clearDynamicTable() {
            this.headerList.clear();
            Arrays.fill(this.dynamicTable, null);
            this.nextHeaderIndex = this.dynamicTable.length - 1;
            this.headerCount = 0;
            this.dynamicTableByteCount = 0;
        }

        private int evictToRecoverBytes(int bytesToRecover) {
            int entriesToEvict = 0;
            if (bytesToRecover > 0) {
                for (int j = this.dynamicTable.length - 1; j >= this.nextHeaderIndex && bytesToRecover > 0; j--) {
                    bytesToRecover -= this.dynamicTable[j].hpackSize;
                    this.dynamicTableByteCount -= this.dynamicTable[j].hpackSize;
                    this.headerCount--;
                    entriesToEvict++;
                }
                System.arraycopy(this.dynamicTable, this.nextHeaderIndex + 1, this.dynamicTable, this.nextHeaderIndex + 1 + entriesToEvict, this.headerCount);
                this.nextHeaderIndex += entriesToEvict;
            }
            return entriesToEvict;
        }

        /* access modifiers changed from: 0000 */
        public void readHeaders() throws IOException {
            while (!this.source.exhausted()) {
                int b = this.source.readByte() & 255;
                if (b == 128) {
                    throw new IOException("index == 0");
                } else if ((b & 128) == 128) {
                    readIndexedHeader(readInt(b, Hpack.PREFIX_7_BITS) - 1);
                } else if (b == 64) {
                    readLiteralHeaderWithIncrementalIndexingNewName();
                } else if ((b & 64) == 64) {
                    readLiteralHeaderWithIncrementalIndexingIndexedName(readInt(b, 63) - 1);
                } else if ((b & 32) == 32) {
                    this.maxDynamicTableByteCount = readInt(b, 31);
                    if (this.maxDynamicTableByteCount < 0 || this.maxDynamicTableByteCount > this.headerTableSizeSetting) {
                        throw new IOException("Invalid dynamic table size update " + this.maxDynamicTableByteCount);
                    }
                    adjustDynamicTableByteCount();
                } else if (b == 16 || b == 0) {
                    readLiteralHeaderWithoutIndexingNewName();
                } else {
                    readLiteralHeaderWithoutIndexingIndexedName(readInt(b, 15) - 1);
                }
            }
        }

        public List<Header> getAndResetHeaderList() {
            List<Header> result = new ArrayList<>(this.headerList);
            this.headerList.clear();
            return result;
        }

        private void readIndexedHeader(int index) throws IOException {
            if (isStaticHeader(index)) {
                this.headerList.add(Hpack.STATIC_HEADER_TABLE[index]);
                return;
            }
            int dynamicTableIndex = dynamicTableIndex(index - Hpack.STATIC_HEADER_TABLE.length);
            if (dynamicTableIndex < 0 || dynamicTableIndex > this.dynamicTable.length - 1) {
                throw new IOException("Header index too large " + (index + 1));
            }
            this.headerList.add(this.dynamicTable[dynamicTableIndex]);
        }

        private int dynamicTableIndex(int index) {
            return this.nextHeaderIndex + 1 + index;
        }

        private void readLiteralHeaderWithoutIndexingIndexedName(int index) throws IOException {
            this.headerList.add(new Header(getName(index), readByteString()));
        }

        private void readLiteralHeaderWithoutIndexingNewName() throws IOException {
            this.headerList.add(new Header(Hpack.checkLowercase(readByteString()), readByteString()));
        }

        private void readLiteralHeaderWithIncrementalIndexingIndexedName(int nameIndex) throws IOException {
            insertIntoDynamicTable(-1, new Header(getName(nameIndex), readByteString()));
        }

        private void readLiteralHeaderWithIncrementalIndexingNewName() throws IOException {
            insertIntoDynamicTable(-1, new Header(Hpack.checkLowercase(readByteString()), readByteString()));
        }

        private ByteString getName(int index) {
            if (isStaticHeader(index)) {
                return Hpack.STATIC_HEADER_TABLE[index].name;
            }
            return this.dynamicTable[dynamicTableIndex(index - Hpack.STATIC_HEADER_TABLE.length)].name;
        }

        private boolean isStaticHeader(int index) {
            return index >= 0 && index <= Hpack.STATIC_HEADER_TABLE.length + -1;
        }

        private void insertIntoDynamicTable(int index, Header entry) {
            this.headerList.add(entry);
            int delta = entry.hpackSize;
            if (index != -1) {
                delta -= this.dynamicTable[dynamicTableIndex(index)].hpackSize;
            }
            if (delta > this.maxDynamicTableByteCount) {
                clearDynamicTable();
                return;
            }
            int entriesEvicted = evictToRecoverBytes((this.dynamicTableByteCount + delta) - this.maxDynamicTableByteCount);
            if (index == -1) {
                if (this.headerCount + 1 > this.dynamicTable.length) {
                    Header[] doubled = new Header[(this.dynamicTable.length * 2)];
                    System.arraycopy(this.dynamicTable, 0, doubled, this.dynamicTable.length, this.dynamicTable.length);
                    this.nextHeaderIndex = this.dynamicTable.length - 1;
                    this.dynamicTable = doubled;
                }
                int index2 = this.nextHeaderIndex;
                this.nextHeaderIndex = index2 - 1;
                this.dynamicTable[index2] = entry;
                this.headerCount++;
            } else {
                this.dynamicTable[index + dynamicTableIndex(index) + entriesEvicted] = entry;
            }
            this.dynamicTableByteCount += delta;
        }

        private int readByte() throws IOException {
            return this.source.readByte() & 255;
        }

        /* access modifiers changed from: 0000 */
        public int readInt(int firstByte, int prefixMask) throws IOException {
            int prefix = firstByte & prefixMask;
            if (prefix < prefixMask) {
                return prefix;
            }
            int result = prefixMask;
            int shift = 0;
            while (true) {
                int b = readByte();
                if ((b & 128) == 0) {
                    return result + (b << shift);
                }
                result += (b & Hpack.PREFIX_7_BITS) << shift;
                shift += 7;
            }
        }

        /* access modifiers changed from: 0000 */
        public ByteString readByteString() throws IOException {
            int firstByte = readByte();
            boolean huffmanDecode = (firstByte & 128) == 128;
            int length = readInt(firstByte, Hpack.PREFIX_7_BITS);
            if (huffmanDecode) {
                return ByteString.of(Huffman.get().decode(this.source.readByteArray((long) length)));
            }
            return this.source.readByteString((long) length);
        }
    }

    static final class Writer {
        private final Buffer out;

        Writer(Buffer out2) {
            this.out = out2;
        }

        /* access modifiers changed from: 0000 */
        public void writeHeaders(List<Header> headerBlock) throws IOException {
            int size = headerBlock.size();
            for (int i = 0; i < size; i++) {
                ByteString name = headerBlock.get(i).name.toAsciiLowercase();
                Integer staticIndex = (Integer) Hpack.NAME_TO_FIRST_INDEX.get(name);
                if (staticIndex != null) {
                    writeInt(staticIndex.intValue() + 1, 15, 0);
                    writeByteString(headerBlock.get(i).value);
                } else {
                    this.out.writeByte(0);
                    writeByteString(name);
                    writeByteString(headerBlock.get(i).value);
                }
            }
        }

        /* access modifiers changed from: 0000 */
        public void writeInt(int value, int prefixMask, int bits) throws IOException {
            if (value < prefixMask) {
                this.out.writeByte(bits | value);
                return;
            }
            this.out.writeByte(bits | prefixMask);
            int value2 = value - prefixMask;
            while (value2 >= 128) {
                this.out.writeByte((value2 & Hpack.PREFIX_7_BITS) | 128);
                value2 >>>= 7;
            }
            this.out.writeByte(value2);
        }

        /* access modifiers changed from: 0000 */
        public void writeByteString(ByteString data) throws IOException {
            writeInt(data.size(), Hpack.PREFIX_7_BITS, 0);
            this.out.write(data);
        }
    }

    private Hpack() {
    }

    private static Map<ByteString, Integer> nameToFirstIndex() {
        Map<ByteString, Integer> result = new LinkedHashMap<>(STATIC_HEADER_TABLE.length);
        for (int i = 0; i < STATIC_HEADER_TABLE.length; i++) {
            if (!result.containsKey(STATIC_HEADER_TABLE[i].name)) {
                result.put(STATIC_HEADER_TABLE[i].name, Integer.valueOf(i));
            }
        }
        return Collections.unmodifiableMap(result);
    }

    /* access modifiers changed from: private */
    public static ByteString checkLowercase(ByteString name) throws IOException {
        int i = 0;
        int length = name.size();
        while (i < length) {
            byte c = name.getByte(i);
            if (c < 65 || c > 90) {
                i++;
            } else {
                throw new IOException("PROTOCOL_ERROR response malformed: mixed case name: " + name.utf8());
            }
        }
        return name;
    }
}