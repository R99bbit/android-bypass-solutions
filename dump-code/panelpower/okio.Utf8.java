package okio;

public final class Utf8 {
    private Utf8() {
    }

    public static long size(String str) {
        return size(str, 0, str.length());
    }

    public static long size(String str, int i, int i2) {
        long j;
        char c;
        if (str == null) {
            throw new IllegalArgumentException("string == null");
        } else if (i < 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("beginIndex < 0: ");
            sb.append(i);
            throw new IllegalArgumentException(sb.toString());
        } else if (i2 < i) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("endIndex < beginIndex: ");
            sb2.append(i2);
            sb2.append(" < ");
            sb2.append(i);
            throw new IllegalArgumentException(sb2.toString());
        } else if (i2 <= str.length()) {
            long j2 = 0;
            while (i < i2) {
                char charAt = str.charAt(i);
                if (charAt < 128) {
                    j2++;
                } else {
                    if (charAt < 2048) {
                        j = 2;
                    } else if (charAt < 55296 || charAt > 57343) {
                        j = 3;
                    } else {
                        int i3 = i + 1;
                        if (i3 < i2) {
                            c = str.charAt(i3);
                        } else {
                            c = 0;
                        }
                        if (charAt > 56319 || c < 56320 || c > 57343) {
                            j2++;
                            i = i3;
                        } else {
                            j2 += 4;
                            i += 2;
                        }
                    }
                    j2 += j;
                }
                i++;
            }
            return j2;
        } else {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("endIndex > string.length: ");
            sb3.append(i2);
            sb3.append(" > ");
            sb3.append(str.length());
            throw new IllegalArgumentException(sb3.toString());
        }
    }
}