package com.ning.http.client.cookie;

import com.ning.http.client.date.CalendarTimeConverter;
import com.ning.http.client.date.TimeConverter;

public class CookieDecoder {
    public static final TimeConverter DEFAULT_TIME_CONVERTER = new CalendarTimeConverter();

    public static Cookie decode(String header) {
        return decode(header, DEFAULT_TIME_CONVERTER);
    }

    public static Cookie decode(String header, TimeConverter timeConverter) {
        String rawValue;
        String str;
        if (timeConverter == null) {
            timeConverter = DEFAULT_TIME_CONVERTER;
        }
        if (header.length() == 0) {
            return null;
        }
        KeyValuePairsParser pairsParser = new KeyValuePairsParser(timeConverter);
        int headerLen = header.length();
        int i = 0;
        while (i != headerLen) {
            char c = header.charAt(i);
            if (c == ',') {
                return pairsParser.cookie();
            }
            if (c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == ' ' || c == ';') {
                i++;
            } else {
                int newNameStart = i;
                int newNameEnd = i;
                if (i == headerLen) {
                    rawValue = null;
                    str = null;
                } else {
                    while (true) {
                        char curChar = header.charAt(i);
                        if (curChar == ';') {
                            newNameEnd = i;
                            rawValue = null;
                            str = null;
                        } else if (curChar == '=') {
                            newNameEnd = i;
                            i++;
                            if (i == headerLen) {
                                rawValue = "";
                                str = rawValue;
                            } else {
                                int newValueStart = i;
                                char c2 = header.charAt(i);
                                if (c2 == '\"' || c2 == '\'') {
                                    StringBuilder sb = new StringBuilder(header.length() - i);
                                    int rawValueStart = i;
                                    int rawValueEnd = i;
                                    char q = c2;
                                    boolean hadBackslash = false;
                                    int i2 = i + 1;
                                    while (true) {
                                        if (i2 == headerLen) {
                                            str = sb.toString();
                                            rawValue = 1 != 0 ? header.substring(rawValueStart, rawValueEnd) : null;
                                            i = i2;
                                        } else if (hadBackslash) {
                                            hadBackslash = false;
                                            int i3 = i2 + 1;
                                            char c3 = header.charAt(i2);
                                            rawValueEnd = i3;
                                            switch (c3) {
                                                case '\"':
                                                case '\'':
                                                case '\\':
                                                    sb.setCharAt(sb.length() - 1, c3);
                                                    i2 = i3;
                                                    break;
                                                default:
                                                    sb.append(c3);
                                                    i2 = i3;
                                                    break;
                                            }
                                        } else {
                                            i = i2 + 1;
                                            char c4 = header.charAt(i2);
                                            rawValueEnd = i;
                                            if (c4 == q) {
                                                str = sb.toString();
                                                rawValue = 1 != 0 ? header.substring(rawValueStart, rawValueEnd) : null;
                                            } else {
                                                sb.append(c4);
                                                if (c4 == '\\') {
                                                    hadBackslash = true;
                                                    i2 = i;
                                                } else {
                                                    i2 = i;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    int semiPos = header.indexOf(59, i);
                                    if (semiPos > 0) {
                                        rawValue = header.substring(newValueStart, semiPos);
                                        str = rawValue;
                                        i = semiPos;
                                    } else {
                                        rawValue = header.substring(newValueStart);
                                        str = rawValue;
                                        i = headerLen;
                                    }
                                }
                            }
                        } else {
                            i++;
                            if (i == headerLen) {
                                newNameEnd = headerLen;
                                rawValue = null;
                                str = null;
                            }
                        }
                    }
                }
                pairsParser.parseKeyValuePair(header, newNameStart, newNameEnd, str, rawValue);
            }
        }
        return pairsParser.cookie();
    }
}