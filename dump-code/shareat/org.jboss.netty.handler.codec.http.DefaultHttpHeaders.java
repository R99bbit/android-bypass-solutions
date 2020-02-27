package org.jboss.netty.handler.codec.http;

import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.Set;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;

public class DefaultHttpHeaders extends HttpHeaders {
    private static final int BUCKET_SIZE = 17;
    private static final Set<String> KNOWN_NAMES = createSet(Names.class);
    private static final Set<String> KNOWN_VALUES = createSet(Values.class);
    private final HeaderEntry[] entries;
    /* access modifiers changed from: private */
    public final HeaderEntry head;
    protected final boolean validate;

    private final class HeaderEntry implements Entry<String, String> {
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
            if (DefaultHttpHeaders.this.validate) {
                DefaultHttpHeaders.this.validateHeaderValue0(value2);
            }
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
            this.current = DefaultHttpHeaders.this.head;
        }

        public boolean hasNext() {
            return this.current.after != DefaultHttpHeaders.this.head;
        }

        public Entry<String, String> next() {
            this.current = this.current.after;
            if (this.current != DefaultHttpHeaders.this.head) {
                return this.current;
            }
            throw new NoSuchElementException();
        }

        public void remove() {
            throw new UnsupportedOperationException();
        }
    }

    private static Set<String> createSet(Class<?> clazz) {
        Field[] arr$;
        Set<String> set = new HashSet<>();
        for (Field f : clazz.getDeclaredFields()) {
            int m = f.getModifiers();
            if (Modifier.isPublic(m) && Modifier.isStatic(m) && Modifier.isFinal(m) && f.getType().isAssignableFrom(String.class)) {
                try {
                    set.add((String) f.get(null));
                } catch (Throwable th) {
                }
            }
        }
        return set;
    }

    private static int hash(String name, boolean validate2) {
        int h = 0;
        for (int i = name.length() - 1; i >= 0; i--) {
            char c = name.charAt(i);
            if (validate2) {
                valideHeaderNameChar(c);
            }
            h = (h * 31) + toLowerCase(c);
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
        if (name1 == name2) {
            return true;
        }
        int nameLen = name1.length();
        if (nameLen != name2.length()) {
            return false;
        }
        for (int i = nameLen - 1; i >= 0; i--) {
            char c1 = name1.charAt(i);
            char c2 = name2.charAt(i);
            if (c1 != c2 && toLowerCase(c1) != toLowerCase(c2)) {
                return false;
            }
        }
        return true;
    }

    private static char toLowerCase(char c) {
        if (c < 'A' || c > 'Z') {
            return c;
        }
        return (char) (c + ' ');
    }

    private static int index(int hash) {
        return hash % 17;
    }

    public DefaultHttpHeaders() {
        this(true);
    }

    public DefaultHttpHeaders(boolean validate2) {
        this.entries = new HeaderEntry[17];
        this.head = new HeaderEntry(-1, null, null);
        HeaderEntry headerEntry = this.head;
        HeaderEntry headerEntry2 = this.head;
        HeaderEntry headerEntry3 = this.head;
        headerEntry2.after = headerEntry3;
        headerEntry.before = headerEntry3;
        this.validate = validate2;
    }

    /* access modifiers changed from: 0000 */
    public void validateHeaderValue0(String headerValue) {
        if (!KNOWN_VALUES.contains(headerValue)) {
            validateHeaderValue(headerValue);
        }
    }

    public HttpHeaders add(String name, Object value) {
        String strVal = toString(value);
        boolean validateName = false;
        if (this.validate) {
            validateHeaderValue0(strVal);
            validateName = !KNOWN_NAMES.contains(name);
        }
        int h = hash(name, validateName);
        add0(h, index(h), name, strVal);
        return this;
    }

    public HttpHeaders add(String name, Iterable<?> values) {
        boolean validateName = false;
        if (this.validate) {
            validateName = !KNOWN_NAMES.contains(name);
        }
        int h = hash(name, validateName);
        int i = index(h);
        for (Object v : values) {
            String vstr = toString(v);
            if (this.validate) {
                validateHeaderValue0(vstr);
            }
            add0(h, i, name, vstr);
        }
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

    public HttpHeaders remove(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        int h = hash(name, false);
        remove0(h, index(h), name);
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

    public HttpHeaders set(String name, Object value) {
        String strVal = toString(value);
        boolean validateName = false;
        if (this.validate) {
            validateHeaderValue0(strVal);
            validateName = !KNOWN_NAMES.contains(name);
        }
        int h = hash(name, validateName);
        int i = index(h);
        remove0(h, i, name);
        add0(h, i, name, strVal);
        return this;
    }

    public HttpHeaders set(String name, Iterable<?> values) {
        if (values == null) {
            throw new NullPointerException("values");
        }
        boolean validateName = false;
        if (this.validate) {
            validateName = !KNOWN_NAMES.contains(name);
        }
        int h = hash(name, validateName);
        int i = index(h);
        remove0(h, i, name);
        for (Object v : values) {
            if (v == null) {
                break;
            }
            String strVal = toString(v);
            if (this.validate) {
                validateHeaderValue0(strVal);
            }
            add0(h, i, name, strVal);
        }
        return this;
    }

    public HttpHeaders clear() {
        Arrays.fill(this.entries, null);
        HeaderEntry headerEntry = this.head;
        HeaderEntry headerEntry2 = this.head;
        HeaderEntry headerEntry3 = this.head;
        headerEntry2.after = headerEntry3;
        headerEntry.before = headerEntry3;
        return this;
    }

    public String get(String name) {
        return get(name, false);
    }

    private String get(String name, boolean last) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        int h = hash(name, false);
        String value = null;
        for (HeaderEntry e = this.entries[index(h)]; e != null; e = e.next) {
            if (e.hash == h && eq(name, e.key)) {
                value = e.value;
                if (last) {
                    break;
                }
            }
        }
        return value;
    }

    public List<String> getAll(String name) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        LinkedList<String> values = new LinkedList<>();
        int h = hash(name, false);
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
        return get(name, true) != null;
    }

    public boolean isEmpty() {
        return this.head == this.head.after;
    }

    public boolean contains(String name, String value, boolean ignoreCaseValue) {
        if (name == null) {
            throw new NullPointerException("name");
        }
        int h = hash(name, false);
        for (HeaderEntry e = this.entries[index(h)]; e != null; e = e.next) {
            if (e.hash == h && eq(name, e.key)) {
                if (ignoreCaseValue) {
                    if (e.value.equalsIgnoreCase(value)) {
                        return true;
                    }
                } else if (e.value.equals(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    public Set<String> names() {
        Set<String> names = new LinkedHashSet<>();
        for (HeaderEntry e = this.head.after; e != this.head; e = e.after) {
            names.add(e.key);
        }
        return names;
    }

    private static String toString(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return (String) value;
        }
        if (value instanceof Number) {
            return value.toString();
        }
        if (value instanceof Date) {
            return HttpHeaderDateFormat.get().format((Date) value);
        }
        if (value instanceof Calendar) {
            return HttpHeaderDateFormat.get().format(((Calendar) value).getTime());
        }
        return value.toString();
    }
}