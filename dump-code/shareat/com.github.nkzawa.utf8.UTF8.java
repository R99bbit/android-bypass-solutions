package com.github.nkzawa.utf8;

import java.util.ArrayList;
import java.util.List;

public class UTF8 {
    private static int[] byteArray;
    private static int byteCount;
    private static int byteIndex;

    public static String encode(String string) {
        int[] codePoints = uc2decode(string);
        int length = codePoints.length;
        int index = -1;
        StringBuilder byteString = new StringBuilder();
        while (true) {
            index++;
            if (index >= length) {
                return byteString.toString();
            }
            byteString.append(encodeCodePoint(codePoints[index]));
        }
    }

    public static String decode(String byteString) throws UTF8Exception {
        byteArray = uc2decode(byteString);
        byteCount = byteArray.length;
        byteIndex = 0;
        List<Integer> codePoints = new ArrayList<>();
        while (true) {
            int tmp = decodeSymbol();
            if (tmp == -1) {
                return ucs2encode(listToArray(codePoints));
            }
            codePoints.add(Integer.valueOf(tmp));
        }
    }

    private static int[] uc2decode(String string) {
        int length = string.length();
        int[] output = new int[string.codePointCount(0, length)];
        int i = 0;
        int counter = 0;
        while (i < length) {
            int value = string.codePointAt(i);
            output[counter] = value;
            i += Character.charCount(value);
            counter++;
        }
        return output;
    }

    private static String encodeCodePoint(int codePoint) {
        StringBuilder symbol = new StringBuilder();
        if ((codePoint & -128) == 0) {
            return symbol.append(Character.toChars(codePoint)).toString();
        }
        if ((codePoint & -2048) == 0) {
            symbol.append(Character.toChars(((codePoint >> 6) & 31) | 192));
        } else if ((-65536 & codePoint) == 0) {
            symbol.append(Character.toChars(((codePoint >> 12) & 15) | 224));
            symbol.append(createByte(codePoint, 6));
        } else if ((-2097152 & codePoint) == 0) {
            symbol.append(Character.toChars(((codePoint >> 18) & 7) | 240));
            symbol.append(createByte(codePoint, 12));
            symbol.append(createByte(codePoint, 6));
        }
        symbol.append(Character.toChars((codePoint & 63) | 128));
        return symbol.toString();
    }

    private static char[] createByte(int codePoint, int shift) {
        return Character.toChars(((codePoint >> shift) & 63) | 128);
    }

    private static int decodeSymbol() throws UTF8Exception {
        if (byteIndex > byteCount) {
            throw new UTF8Exception((String) "Invalid byte index");
        } else if (byteIndex == byteCount) {
            return -1;
        } else {
            int byte1 = byteArray[byteIndex] & 255;
            byteIndex++;
            if ((byte1 & 128) == 0) {
                return byte1;
            }
            if ((byte1 & 224) == 192) {
                int codePoint = ((byte1 & 31) << 6) | readContinuationByte();
                if (codePoint >= 128) {
                    return codePoint;
                }
                throw new UTF8Exception((String) "Invalid continuation byte");
            } else if ((byte1 & 240) == 224) {
                int codePoint2 = ((byte1 & 15) << 12) | (readContinuationByte() << 6) | readContinuationByte();
                if (codePoint2 >= 2048) {
                    return codePoint2;
                }
                throw new UTF8Exception((String) "Invalid continuation byte");
            } else {
                if ((byte1 & 248) == 240) {
                    int codePoint3 = ((byte1 & 15) << 18) | (readContinuationByte() << 12) | (readContinuationByte() << 6) | readContinuationByte();
                    if (codePoint3 >= 65536 && codePoint3 <= 1114111) {
                        return codePoint3;
                    }
                }
                throw new UTF8Exception((String) "Invalid continuation byte");
            }
        }
    }

    private static int readContinuationByte() throws UTF8Exception {
        if (byteIndex >= byteCount) {
            throw new UTF8Exception((String) "Invalid byte index");
        }
        int continuationByte = byteArray[byteIndex] & 255;
        byteIndex++;
        if ((continuationByte & 192) == 128) {
            return continuationByte & 63;
        }
        throw new UTF8Exception((String) "Invalid continuation byte");
    }

    private static String ucs2encode(int[] array) {
        StringBuilder output = new StringBuilder();
        for (int value : array) {
            output.appendCodePoint(value);
        }
        return output.toString();
    }

    private static int[] listToArray(List<Integer> list) {
        int size = list.size();
        int[] array = new int[size];
        for (int i = 0; i < size; i++) {
            array[i] = list.get(i).intValue();
        }
        return array;
    }
}