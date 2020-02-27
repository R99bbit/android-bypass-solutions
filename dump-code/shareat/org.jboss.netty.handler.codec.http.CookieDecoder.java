package org.jboss.netty.handler.codec.http;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jboss.netty.util.internal.StringUtil;

public class CookieDecoder {
    private static final char COMMA = ',';

    public CookieDecoder() {
    }

    @Deprecated
    public CookieDecoder(boolean lenient) {
    }

    public Set<Cookie> decode(String header) {
        int i;
        ArrayList arrayList = new ArrayList(8);
        ArrayList arrayList2 = new ArrayList(8);
        extractKeyValuePairs(header, arrayList, arrayList2);
        if (arrayList.isEmpty()) {
            return Collections.emptySet();
        }
        int version = 0;
        if (((String) arrayList.get(0)).equalsIgnoreCase("Version")) {
            try {
                version = Integer.parseInt((String) arrayList2.get(0));
            } catch (NumberFormatException e) {
            }
            i = 1;
        } else {
            i = 0;
        }
        if (arrayList.size() <= i) {
            return Collections.emptySet();
        }
        Set<Cookie> cookies = new TreeSet<>();
        while (i < arrayList.size()) {
            String name = (String) arrayList.get(i);
            String value = (String) arrayList2.get(i);
            if (value == null) {
                value = "";
            }
            Cookie c = new DefaultCookie(name, value);
            boolean discard = false;
            boolean secure = false;
            boolean httpOnly = false;
            String comment = null;
            String commentURL = null;
            String domain = null;
            String path = null;
            int maxAge = Integer.MIN_VALUE;
            ArrayList arrayList3 = new ArrayList(2);
            int j = i + 1;
            while (j < arrayList.size()) {
                String name2 = (String) arrayList.get(j);
                String value2 = (String) arrayList2.get(j);
                if (!"Discard".equalsIgnoreCase(name2)) {
                    if (!"Secure".equalsIgnoreCase(name2)) {
                        if (!"HTTPOnly".equalsIgnoreCase(name2)) {
                            if (!"Comment".equalsIgnoreCase(name2)) {
                                if (!"CommentURL".equalsIgnoreCase(name2)) {
                                    if (!"Domain".equalsIgnoreCase(name2)) {
                                        if (!"Path".equalsIgnoreCase(name2)) {
                                            if (!"Expires".equalsIgnoreCase(name2)) {
                                                if (!"Max-Age".equalsIgnoreCase(name2)) {
                                                    if (!"Version".equalsIgnoreCase(name2)) {
                                                        if (!"Port".equalsIgnoreCase(name2)) {
                                                            break;
                                                        }
                                                        for (String s1 : StringUtil.split(value2, COMMA)) {
                                                            try {
                                                                arrayList3.add(Integer.valueOf(s1));
                                                            } catch (NumberFormatException e2) {
                                                            }
                                                        }
                                                    } else {
                                                        version = Integer.parseInt(value2);
                                                    }
                                                } else {
                                                    maxAge = Integer.parseInt(value2);
                                                }
                                            } else {
                                                try {
                                                    long maxAgeMillis = HttpHeaderDateFormat.get().parse(value2).getTime() - System.currentTimeMillis();
                                                    maxAge = ((int) (maxAgeMillis / 1000)) + (maxAgeMillis % 1000 != 0 ? 1 : 0);
                                                } catch (ParseException e3) {
                                                }
                                            }
                                        } else {
                                            path = value2;
                                        }
                                    } else {
                                        domain = value2;
                                    }
                                } else {
                                    commentURL = value2;
                                }
                            } else {
                                comment = value2;
                            }
                        } else {
                            httpOnly = true;
                        }
                    } else {
                        secure = true;
                    }
                } else {
                    discard = true;
                }
                j++;
                i++;
            }
            c.setVersion(version);
            c.setMaxAge(maxAge);
            c.setPath(path);
            c.setDomain(domain);
            c.setSecure(secure);
            c.setHttpOnly(httpOnly);
            if (version > 0) {
                c.setComment(comment);
            }
            if (version > 1) {
                c.setCommentUrl(commentURL);
                c.setPorts((Iterable<Integer>) arrayList3);
                c.setDiscard(discard);
            }
            cookies.add(c);
            i++;
        }
        return cookies;
    }

    private static void extractKeyValuePairs(String header, List<String> names, List<String> values) {
        String name;
        String value;
        int headerLen = header.length();
        int i = 0;
        while (i != headerLen) {
            switch (header.charAt(i)) {
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case ' ':
                case ',':
                case ';':
                    i++;
                    break;
                default:
                    while (i != headerLen) {
                        if (header.charAt(i) != '$') {
                            if (i != headerLen) {
                                int newNameStart = i;
                                while (true) {
                                    switch (header.charAt(i)) {
                                        case ';':
                                            name = header.substring(newNameStart, i);
                                            value = null;
                                            break;
                                        case '=':
                                            name = header.substring(newNameStart, i);
                                            i++;
                                            if (i != headerLen) {
                                                int newValueStart = i;
                                                char c = header.charAt(i);
                                                if (c != '\"' && c != '\'') {
                                                    int semiPos = header.indexOf(59, i);
                                                    if (semiPos <= 0) {
                                                        value = header.substring(newValueStart);
                                                        i = headerLen;
                                                        break;
                                                    } else {
                                                        value = header.substring(newValueStart, semiPos);
                                                        i = semiPos;
                                                        break;
                                                    }
                                                } else {
                                                    StringBuilder newValueBuf = new StringBuilder(header.length() - i);
                                                    char q = c;
                                                    boolean hadBackslash = false;
                                                    int i2 = i + 1;
                                                    while (true) {
                                                        if (i2 == headerLen) {
                                                            value = newValueBuf.toString();
                                                            i = i2;
                                                            break;
                                                        } else if (hadBackslash) {
                                                            hadBackslash = false;
                                                            int i3 = i2 + 1;
                                                            char c2 = header.charAt(i2);
                                                            switch (c2) {
                                                                case '\"':
                                                                case '\'':
                                                                case '\\':
                                                                    newValueBuf.setCharAt(newValueBuf.length() - 1, c2);
                                                                    i2 = i3;
                                                                    break;
                                                                default:
                                                                    newValueBuf.append(c2);
                                                                    i2 = i3;
                                                                    break;
                                                            }
                                                        } else {
                                                            i = i2 + 1;
                                                            char c3 = header.charAt(i2);
                                                            if (c3 == q) {
                                                                value = newValueBuf.toString();
                                                                break;
                                                            } else {
                                                                newValueBuf.append(c3);
                                                                if (c3 == '\\') {
                                                                    hadBackslash = true;
                                                                    i2 = i;
                                                                } else {
                                                                    i2 = i;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                value = "";
                                                break;
                                            }
                                            break;
                                        default:
                                            i++;
                                            if (i == headerLen) {
                                                name = header.substring(newNameStart);
                                                value = null;
                                                break;
                                            }
                                    }
                                }
                            } else {
                                name = null;
                                value = null;
                            }
                            names.add(name);
                            values.add(value);
                            break;
                        } else {
                            i++;
                        }
                    }
                    return;
            }
        }
    }
}