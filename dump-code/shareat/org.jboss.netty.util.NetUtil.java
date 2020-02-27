package org.jboss.netty.util;

import com.facebook.appevents.AppEventsConstants;
import java.util.ArrayList;
import java.util.StringTokenizer;

public final class NetUtil {
    public static byte[] createByteArrayFromIpAddressString(String ipAddressString) {
        if (isValidIpV4Address(ipAddressString)) {
            StringTokenizer tokenizer = new StringTokenizer(ipAddressString, ".");
            byte[] byteAddress = new byte[4];
            for (int i = 0; i < 4; i++) {
                byteAddress[i] = (byte) Integer.parseInt(tokenizer.nextToken());
            }
            return byteAddress;
        } else if (!isValidIpV6Address(ipAddressString)) {
            return null;
        } else {
            if (ipAddressString.charAt(0) == '[') {
                ipAddressString = ipAddressString.substring(1, ipAddressString.length() - 1);
            }
            StringTokenizer tokenizer2 = new StringTokenizer(ipAddressString, ":.", true);
            ArrayList<String> hexStrings = new ArrayList<>();
            ArrayList<String> decStrings = new ArrayList<>();
            String token = "";
            String prevToken = "";
            int doubleColonIndex = -1;
            while (tokenizer2.hasMoreTokens()) {
                prevToken = token;
                token = tokenizer2.nextToken();
                if (":".equals(token)) {
                    if (":".equals(prevToken)) {
                        doubleColonIndex = hexStrings.size();
                    } else if (prevToken.length() > 0) {
                        hexStrings.add(prevToken);
                    }
                } else if (".".equals(token)) {
                    decStrings.add(prevToken);
                }
            }
            if (":".equals(prevToken)) {
                if (":".equals(token)) {
                    doubleColonIndex = hexStrings.size();
                } else {
                    hexStrings.add(token);
                }
            } else if (".".equals(prevToken)) {
                decStrings.add(token);
            }
            int hexStringsLength = 8;
            if (!decStrings.isEmpty()) {
                hexStringsLength = 8 - 2;
            }
            if (doubleColonIndex != -1) {
                int numberToInsert = hexStringsLength - hexStrings.size();
                for (int i2 = 0; i2 < numberToInsert; i2++) {
                    hexStrings.add(doubleColonIndex, AppEventsConstants.EVENT_PARAM_VALUE_NO);
                }
            }
            byte[] ipByteArray = new byte[16];
            for (int i3 = 0; i3 < hexStrings.size(); i3++) {
                convertToBytes(hexStrings.get(i3), ipByteArray, i3 * 2);
            }
            for (int i4 = 0; i4 < decStrings.size(); i4++) {
                ipByteArray[i4 + 12] = (byte) (Integer.parseInt(decStrings.get(i4)) & 255);
            }
            return ipByteArray;
        }
    }

    private static void convertToBytes(String hexWord, byte[] ipByteArray, int byteIndex) {
        int hexWordIndex;
        int hexWordIndex2;
        int hexWordLength = hexWord.length();
        ipByteArray[byteIndex] = 0;
        ipByteArray[byteIndex + 1] = 0;
        if (hexWordLength > 3) {
            hexWordIndex = 0 + 1;
            ipByteArray[byteIndex] = (byte) (ipByteArray[byteIndex] | (getIntValue(hexWord.charAt(0)) << 4));
        } else {
            hexWordIndex = 0;
        }
        if (hexWordLength > 2) {
            ipByteArray[byteIndex] = (byte) (ipByteArray[byteIndex] | getIntValue(hexWord.charAt(hexWordIndex)));
            hexWordIndex++;
        }
        if (hexWordLength > 1) {
            hexWordIndex2 = hexWordIndex + 1;
            int i = byteIndex + 1;
            ipByteArray[i] = (byte) (ipByteArray[i] | (getIntValue(hexWord.charAt(hexWordIndex)) << 4));
        } else {
            hexWordIndex2 = hexWordIndex;
        }
        int i2 = byteIndex + 1;
        ipByteArray[i2] = (byte) (ipByteArray[i2] | (getIntValue(hexWord.charAt(hexWordIndex2)) & 15));
    }

    static int getIntValue(char c) {
        switch (c) {
            case '0':
                return 0;
            case '1':
                return 1;
            case '2':
                return 2;
            case '3':
                return 3;
            case '4':
                return 4;
            case '5':
                return 5;
            case '6':
                return 6;
            case '7':
                return 7;
            case '8':
                return 8;
            case '9':
                return 9;
            default:
                switch (Character.toLowerCase(c)) {
                    case 'a':
                        return 10;
                    case 'b':
                        return 11;
                    case 'c':
                        return 12;
                    case 'd':
                        return 13;
                    case 'e':
                        return 14;
                    case 'f':
                        return 15;
                    default:
                        return 0;
                }
        }
    }

    public static boolean isValidIpV6Address(String ipAddress) {
        int length = ipAddress.length();
        boolean doubleColon = false;
        int numberOfColons = 0;
        int numberOfPeriods = 0;
        int numberOfPercent = 0;
        StringBuilder word = new StringBuilder();
        char c = 0;
        int offset = 0;
        if (length < 2) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            char prevChar = c;
            c = ipAddress.charAt(i);
            switch (c) {
                case '%':
                    if (numberOfColons == 0) {
                        return false;
                    }
                    numberOfPercent++;
                    if (i + 1 >= length) {
                        return false;
                    }
                    try {
                        Integer.parseInt(ipAddress.substring(i + 1));
                        break;
                    } catch (NumberFormatException e) {
                        return false;
                    }
                case '.':
                    numberOfPeriods++;
                    if (numberOfPeriods > 3) {
                        return false;
                    }
                    if (!isValidIp4Word(word.toString())) {
                        return false;
                    }
                    if (numberOfColons != 6 && !doubleColon) {
                        return false;
                    }
                    if (numberOfColons != 7 || ipAddress.charAt(offset) == ':' || ipAddress.charAt(offset + 1) == ':') {
                        word.delete(0, word.length());
                        break;
                    } else {
                        return false;
                    }
                case ':':
                    if (i != offset || (ipAddress.length() > i && ipAddress.charAt(i + 1) == ':')) {
                        numberOfColons++;
                        if (numberOfColons <= 7) {
                            if (numberOfPeriods <= 0) {
                                if (prevChar == ':') {
                                    if (doubleColon) {
                                        return false;
                                    }
                                    doubleColon = true;
                                }
                                word.delete(0, word.length());
                                break;
                            } else {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                case '[':
                    if (i == 0) {
                        if (ipAddress.charAt(length - 1) == ']') {
                            offset = 1;
                            if (length >= 4) {
                                break;
                            } else {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                case ']':
                    if (i == length - 1) {
                        if (ipAddress.charAt(0) == '[') {
                            break;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                default:
                    if (numberOfPercent == 0) {
                        if (word != null && word.length() > 3) {
                            return false;
                        }
                        if (!isValidHexChar(c)) {
                            return false;
                        }
                    }
                    word.append(c);
                    break;
            }
        }
        if (numberOfPeriods > 0) {
            if (numberOfPeriods != 3 || !isValidIp4Word(word.toString()) || numberOfColons >= 7) {
                return false;
            }
        } else if (numberOfColons != 7 && !doubleColon) {
            return false;
        } else {
            if (numberOfPercent == 0 && word.length() == 0 && ipAddress.charAt((length - 1) - offset) == ':' && ipAddress.charAt((length - 2) - offset) != ':') {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidIp4Word(String word) {
        if (word.length() < 1 || word.length() > 3) {
            return false;
        }
        for (int i = 0; i < word.length(); i++) {
            char c = word.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        if (Integer.parseInt(word) <= 255) {
            return true;
        }
        return false;
    }

    static boolean isValidHexChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    public static boolean isValidIpV4Address(String value) {
        int periods = 0;
        int length = value.length();
        if (length > 15) {
            return false;
        }
        StringBuilder word = new StringBuilder();
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (c == '.') {
                periods++;
                if (periods > 3 || word.length() == 0 || Integer.parseInt(word.toString()) > 255) {
                    return false;
                }
                word.delete(0, word.length());
            } else if (!Character.isDigit(c) || word.length() > 2) {
                return false;
            } else {
                word.append(c);
            }
        }
        if (word.length() == 0 || Integer.parseInt(word.toString()) > 255 || periods != 3) {
            return false;
        }
        return true;
    }

    private NetUtil() {
    }
}