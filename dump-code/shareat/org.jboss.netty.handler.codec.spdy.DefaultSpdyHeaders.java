package org.jboss.netty.handler.codec.spdy;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeSet;

public class DefaultSpdyHeaders extends SpdyHeaders {
    private static final int BUCKET_SIZE = 17;
    private final HeaderEntry[] entries = new HeaderEntry[17];
    /* access modifiers changed from: private */
    public final HeaderEntry head = new HeaderEntry(-1, null, null);

    private static final class HeaderEntry implements Entry<String, String> {
        HeaderEntry after;
        HeaderEntry before;
        final int hash;
        final String key;
        HeaderEntry next;
        String value;

        HeaderEntry(int hash2, String key2, String value2) {
            this.hash = hash2;
            this.key = key2;
            this.value = value2;
        }

        /* access modifiers changed from: 0000 */
        public void remove() {
            this.before.after = this.after;
            this.after.before = this.before;
        }

        /* access modifiers changed from: 0000 */
        public void addBefore(HeaderEntry e) {
            this.after = e;
            this.before = e.before;
            this.before.after = this;
            this.after.before = this;
        }

        public String getKey() {
            return this.key;
        }

        public String getValue() {
            return this.value;
        }

        public String setValue(String value2) {
            if (value2 == null) {
                throw new NullPointerException(Param.VALUE);
            }
            SpdyCodecUtil.validateHeaderValue(value2);
            String oldValue = this.value;
            this.value = value2;
            return oldValue;
        }

        public String toString() {
            return this.key + '=' + this.value;
        }
    }

    private final class HeaderIterator implements Iterator<Entry<String, String>> {
        private HeaderEntry current;

        private HeaderIterator() {
            this.current = DefaultSpdyHeaders.this.head;
        }

        public boolean hasNext() {
            return this.current.after != DefaultSpdyHeaders.this.head;
        }

        public Entry<String, String> next() {
            this.current = this.current.after;
            if (this.current != DefaultSpdyHeaders.this.head) {
                return this.current;
            }
            throw new NoSuchElementException();
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    private static int hash(String name) {
        int h = 0;
        for (int i = name.length() - 1; i >= 0; i--) {
            char c = name.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ' ');
            }
            h = (h * 31) + c;
        }
        if (h > 0) {
            return h;
        }
        if (h == Integer.MIN_VALUE) {
            return ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }
        return -h;
    }

    private static boolean eq(String name1, String name2) {
        int nameLen = name1.length();
        if (nameLen != name2.length()) {
            return false;
        }
        for (int i = nameLen - 1; i >= 0; i--) {
            char c1 = name1.charAt(i);
            char c2 = name2.charAt(i);
            if (c1 != c2) {
                if (c1 >= 'A' && c1 <= 'Z') {
                    c1 = (char) (c1 + ' ');
                }
                if (c2 >= 'A' && c2 <= 'Z') {
                    c2 = (char) (c2 + ' ');
                }
                if (c1 != c2) {
                    return false;
                }
            }
        }
        return true;
    }

    private static int index(int hash) {
        return hash % 17;
    }

    DefaultSpdyHeaders() {
        HeaderEntry headerEntry = this.head;
        HeaderEntry headerEntry2 = this.head;
        HeaderEntry headerEntry3 = this.head;
        headerEntry2.after = headerEntry3;
        headerEntry.before = headerEntry3;
    }

    public SpdyHeaders add(String name, Object value) {
        String lowerCaseName = name.toLowerCase();
        SpdyCodecUtil.validateHeaderName(lowerCaseName);
        String strVal = toString(value);
        SpdyCodecUtil.validateHeaderValue(strVal);
        int h = hash(lowerCaseName);
        add0(h, index(h), lowerCaseName, strVal);
        return this;
    }

    private void add0(int h, int i, String name, String value) {
        HeaderEntry e = this.entries[i];
        HeaderEntry[] headerEntryArr = this.entries;
        HeaderEntry newEntry = new HeaderEntry(h, name, value);
        headerEntryArr[i] = newEntry;
        newEntry.next = e;
        newEntry.addBefore(this.head);
    }

    public SpdyHeaders remove(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        String lowerCaseName = name.toLowerCase();
        int h = hash(lowerCaseName);
        remove0(h, index(h), lowerCaseName);
        return this;
    }

    /* JADX WARNING: CFG modification limit reached, blocks count: 125 */
    private void remove0(int h, int i, String name) {
        HeaderEntry e = this.entries[i];
        if (e != null) {
            while (true) {
                if (e.hash == h && eq(name, e.key)) {
                    e.remove();
                    HeaderEntry next = e.next;
                    if (next == null) {
                        this.entries[i] = null;
                        break;
                    } else {
                        this.entries[i] = next;
                        e = next;
                    }
                }
            }
            loop1:
            while (true) {
                HeaderEntry next2 = e.next;
                if (next2 == null) {
                    break loop1;
                } else if (next2.hash != h || !eq(name, next2.key)) {
                    e = next2;
                } else {
                    e.next = next2.next;
                    next2.remove();
                }
            }
        }
    }

    public SpdyHeaders set(String name, Object value) {
        String lowerCaseName = name.toLowerCase();
        SpdyCodecUtil.validateHeaderName(lowerCaseName);
        String strVal = toString(value);
        SpdyCodecUtil.validateHeaderValue(strVal);
        int h = hash(lowerCaseName);
        int i = index(h);
        remove0(h, i, lowerCaseName);
        add0(h, i, lowerCaseName, strVal);
        return this;
    }

    public SpdyHeaders set(String name, Iterable<?> values) {
        if (values == null) {
            throw new NullPointerException("values");
        }
        String lowerCaseName = name.toLowerCase();
        SpdyCodecUtil.validateHeaderName(lowerCaseName);
        int h = hash(lowerCaseName);
        int i = index(h);
        remove0(h, i, lowerCaseName);
        for (Object v : values) {
            if (v == null) {
                break;
            }
            String strVal = toString(v);
            SpdyCodecUtil.validateHeaderValue(strVal);
            add0(h, i, lowerCaseName, strVal);
        }
        return this;
    }

    public SpdyHeaders clear() {
        for (int i = 0; i < this.entries.length; i++) {
            this.entries[i] = null;
        }
        HeaderEntry headerEntry = this.head;
        HeaderEntry headerEntry2 = this.head;
        HeaderEntry headerEntry3 = this.head;
        headerEntry2.after = headerEntry3;
        headerEntry.before = headerEntry3;
        return this;
    }

    public String get(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        int h = hash(name);
        for (HeaderEntry e = this.entries[index(h)]; e != null; e = e.next) {
            if (e.hash == h && eq(name, e.key)) {
                return e.value;
            }
        }
        return null;
    }

    public List<String> getAll(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        LinkedList<String> values = new LinkedList<>();
        int h = hash(name);
        for (HeaderEntry e = this.entries[index(h)]; e != null; e = e.next) {
            if (e.hash == h && eq(name, e.key)) {
                values.addFirst(e.value);
            }
        }
        return values;
    }

    public List<Entry<String, String>> entries() {
        List<Entry<String, String>> all = new LinkedList<>();
        for (HeaderEntry e = this.head.after; e != this.head; e = e.after) {
            all.add(e);
        }
        return all;
    }

    public Iterator<Entry<String, String>> iterator() {
        return new HeaderIterator();
    }

    public boolean contains(String name) {
        return get(name) != null;
    }

    public Set<String> names() {
        Set<String> names = new TreeSet<>();
        for (HeaderEntry e = this.head.after; e != this.head; e = e.after) {
            names.add(e.key);
        }
        return names;
    }

    public SpdyHeaders add(String name, Iterable<?> values) {
        SpdyCodecUtil.validateHeaderValue(name);
        int h = hash(name);
        int i = index(h);
        for (Object v : values) {
            String vstr = toString(v);
            SpdyCodecUtil.validateHeaderValue(vstr);
            add0(h, i, name, vstr);
        }
        return this;
    }

    public boolean isEmpty() {
        return this.head == this.head.after;
    }

    private static String toString(Object value) {
        if (value == null) {
            return null;
        }
        return value.toString();
    }
}