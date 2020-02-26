package okhttp3;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.annotation.Nullable;
import okhttp3.internal.Util;
import okhttp3.internal.http.HttpDate;

public final class Headers {
    private final String[] namesAndValues;

    public static final class Builder {
        final List<String> namesAndValues = new ArrayList(20);

        /* access modifiers changed from: 0000 */
        public Builder addLenient(String str) {
            int indexOf = str.indexOf(":", 1);
            if (indexOf != -1) {
                return addLenient(str.substring(0, indexOf), str.substring(indexOf + 1));
            }
            if (str.startsWith(":")) {
                return addLenient("", str.substring(1));
            }
            return addLenient("", str);
        }

        public Builder add(String str) {
            int indexOf = str.indexOf(":");
            if (indexOf != -1) {
                return add(str.substring(0, indexOf).trim(), str.substring(indexOf + 1));
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Unexpected header: ");
            sb.append(str);
            throw new IllegalArgumentException(sb.toString());
        }

        public Builder add(String str, String str2) {
            checkNameAndValue(str, str2);
            return addLenient(str, str2);
        }

        /* access modifiers changed from: 0000 */
        public Builder addLenient(String str, String str2) {
            this.namesAndValues.add(str);
            this.namesAndValues.add(str2.trim());
            return this;
        }

        public Builder removeAll(String str) {
            int i = 0;
            while (i < this.namesAndValues.size()) {
                if (str.equalsIgnoreCase(this.namesAndValues.get(i))) {
                    this.namesAndValues.remove(i);
                    this.namesAndValues.remove(i);
                    i -= 2;
                }
                i += 2;
            }
            return this;
        }

        public Builder set(String str, String str2) {
            checkNameAndValue(str, str2);
            removeAll(str);
            addLenient(str, str2);
            return this;
        }

        private void checkNameAndValue(String str, String str2) {
            if (str == null) {
                throw new NullPointerException("name == null");
            } else if (!str.isEmpty()) {
                int length = str.length();
                for (int i = 0; i < length; i++) {
                    char charAt = str.charAt(i);
                    if (charAt <= ' ' || charAt >= 127) {
                        throw new IllegalArgumentException(Util.format("Unexpected char %#04x at %d in header name: %s", Integer.valueOf(charAt), Integer.valueOf(i), str));
                    }
                }
                if (str2 != null) {
                    int length2 = str2.length();
                    int i2 = 0;
                    while (i2 < length2) {
                        char charAt2 = str2.charAt(i2);
                        if ((charAt2 > 31 || charAt2 == 9) && charAt2 < 127) {
                            i2++;
                        } else {
                            throw new IllegalArgumentException(Util.format("Unexpected char %#04x at %d in %s value: %s", Integer.valueOf(charAt2), Integer.valueOf(i2), str, str2));
                        }
                    }
                    return;
                }
                StringBuilder sb = new StringBuilder();
                sb.append("value for name ");
                sb.append(str);
                sb.append(" == null");
                throw new NullPointerException(sb.toString());
            } else {
                throw new IllegalArgumentException("name is empty");
            }
        }

        public String get(String str) {
            for (int size = this.namesAndValues.size() - 2; size >= 0; size -= 2) {
                if (str.equalsIgnoreCase(this.namesAndValues.get(size))) {
                    return this.namesAndValues.get(size + 1);
                }
            }
            return null;
        }

        public Headers build() {
            return new Headers(this);
        }
    }

    Headers(Builder builder) {
        this.namesAndValues = (String[]) builder.namesAndValues.toArray(new String[builder.namesAndValues.size()]);
    }

    private Headers(String[] strArr) {
        this.namesAndValues = strArr;
    }

    @Nullable
    public String get(String str) {
        return get(this.namesAndValues, str);
    }

    @Nullable
    public Date getDate(String str) {
        String str2 = get(str);
        if (str2 != null) {
            return HttpDate.parse(str2);
        }
        return null;
    }

    public int size() {
        return this.namesAndValues.length / 2;
    }

    public String name(int i) {
        return this.namesAndValues[i * 2];
    }

    public String value(int i) {
        return this.namesAndValues[(i * 2) + 1];
    }

    public Set<String> names() {
        TreeSet treeSet = new TreeSet(String.CASE_INSENSITIVE_ORDER);
        int size = size();
        for (int i = 0; i < size; i++) {
            treeSet.add(name(i));
        }
        return Collections.unmodifiableSet(treeSet);
    }

    public List<String> values(String str) {
        int size = size();
        ArrayList arrayList = null;
        for (int i = 0; i < size; i++) {
            if (str.equalsIgnoreCase(name(i))) {
                if (arrayList == null) {
                    arrayList = new ArrayList(2);
                }
                arrayList.add(value(i));
            }
        }
        if (arrayList != null) {
            return Collections.unmodifiableList(arrayList);
        }
        return Collections.emptyList();
    }

    public long byteCount() {
        String[] strArr = this.namesAndValues;
        long length = (long) (strArr.length * 2);
        for (int i = 0; i < strArr.length; i++) {
            length += (long) this.namesAndValues[i].length();
        }
        return length;
    }

    public Builder newBuilder() {
        Builder builder = new Builder();
        Collections.addAll(builder.namesAndValues, this.namesAndValues);
        return builder;
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof Headers) && Arrays.equals(((Headers) obj).namesAndValues, this.namesAndValues);
    }

    public int hashCode() {
        return Arrays.hashCode(this.namesAndValues);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        int size = size();
        for (int i = 0; i < size; i++) {
            sb.append(name(i));
            sb.append(": ");
            sb.append(value(i));
            sb.append("\n");
        }
        return sb.toString();
    }

    public Map<String, List<String>> toMultimap() {
        TreeMap treeMap = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        int size = size();
        for (int i = 0; i < size; i++) {
            String lowerCase = name(i).toLowerCase(Locale.US);
            List list = (List) treeMap.get(lowerCase);
            if (list == null) {
                list = new ArrayList(2);
                treeMap.put(lowerCase, list);
            }
            list.add(value(i));
        }
        return treeMap;
    }

    private static String get(String[] strArr, String str) {
        for (int length = strArr.length - 2; length >= 0; length -= 2) {
            if (str.equalsIgnoreCase(strArr[length])) {
                return strArr[length + 1];
            }
        }
        return null;
    }

    public static Headers of(String... strArr) {
        if (strArr == null) {
            throw new NullPointerException("namesAndValues == null");
        } else if (strArr.length % 2 == 0) {
            String[] strArr2 = (String[]) strArr.clone();
            int i = 0;
            while (i < strArr2.length) {
                if (strArr2[i] != null) {
                    strArr2[i] = strArr2[i].trim();
                    i++;
                } else {
                    throw new IllegalArgumentException("Headers cannot be null");
                }
            }
            int i2 = 0;
            while (i2 < strArr2.length) {
                String str = strArr2[i2];
                String str2 = strArr2[i2 + 1];
                if (str.length() != 0 && str.indexOf(0) == -1 && str2.indexOf(0) == -1) {
                    i2 += 2;
                } else {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Unexpected header: ");
                    sb.append(str);
                    sb.append(": ");
                    sb.append(str2);
                    throw new IllegalArgumentException(sb.toString());
                }
            }
            return new Headers(strArr2);
        } else {
            throw new IllegalArgumentException("Expected alternating header names and values");
        }
    }

    public static Headers of(Map<String, String> map) {
        if (map != null) {
            String[] strArr = new String[(map.size() * 2)];
            int i = 0;
            for (Entry next : map.entrySet()) {
                if (next.getKey() == null || next.getValue() == null) {
                    throw new IllegalArgumentException("Headers cannot be null");
                }
                String trim = ((String) next.getKey()).trim();
                String trim2 = ((String) next.getValue()).trim();
                if (trim.length() != 0 && trim.indexOf(0) == -1 && trim2.indexOf(0) == -1) {
                    strArr[i] = trim;
                    strArr[i + 1] = trim2;
                    i += 2;
                } else {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Unexpected header: ");
                    sb.append(trim);
                    sb.append(": ");
                    sb.append(trim2);
                    throw new IllegalArgumentException(sb.toString());
                }
            }
            return new Headers(strArr);
        }
        throw new NullPointerException("headers == null");
    }
}