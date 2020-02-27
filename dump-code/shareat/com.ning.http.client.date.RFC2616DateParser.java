package com.ning.http.client.date;

import com.ning.http.client.date.RFC2616Date.Builder;

public class RFC2616DateParser {
    private final int length;
    private final int offset;
    private final String string;

    private static class Tokens {
        public final int[] ends;
        public final int length;
        public final int[] starts;

        public Tokens(int[] starts2, int[] ends2, int length2) {
            this.starts = starts2;
            this.ends = ends2;
            this.length = length2;
        }
    }

    public RFC2616DateParser(String string2) {
        this(string2, 0, string2.length());
    }

    public RFC2616DateParser(String string2, int offset2, int length2) {
        if (string2.length() + offset2 < length2) {
            throw new IllegalArgumentException("String length doesn't match offset and length");
        }
        this.string = string2;
        this.offset = offset2;
        this.length = length2;
    }

    private Tokens tokenize() {
        int tokenCount;
        int tokenCount2;
        int[] starts = new int[8];
        int[] ends = new int[8];
        boolean inToken = false;
        int end = this.offset + this.length;
        int i = this.offset;
        int tokenCount3 = 0;
        while (i < end) {
            char c = this.string.charAt(i);
            if (c == ' ' || c == ',' || c == '-' || c == ':') {
                if (inToken) {
                    tokenCount2 = tokenCount3 + 1;
                    ends[tokenCount3] = i;
                    inToken = false;
                }
                tokenCount2 = tokenCount3;
            } else {
                if (!inToken) {
                    starts[tokenCount3] = i;
                    inToken = true;
                    tokenCount2 = tokenCount3;
                }
                tokenCount2 = tokenCount3;
            }
            i++;
            tokenCount3 = tokenCount2;
        }
        if (1 != 0) {
            tokenCount = tokenCount3 + 1;
            ends[tokenCount3] = end;
        } else {
            tokenCount = tokenCount3;
        }
        return new Tokens(starts, ends, tokenCount);
    }

    public RFC2616Date parse() {
        Tokens tokens = tokenize();
        if (tokens.length != 7 && tokens.length != 8) {
            return null;
        }
        if (isDigit(this.string.charAt(tokens.starts[1]))) {
            return buildDate(tokens);
        }
        return buildANSICDate(tokens);
    }

    private RFC2616Date buildDate(Tokens tokens) {
        Builder dateBuilder = new Builder();
        if (!isValidDayOfMonth(tokens.starts[1], tokens.ends[1], dateBuilder) || !isValidMonth(tokens.starts[2], tokens.ends[2], dateBuilder) || !isValidYear(tokens.starts[3], tokens.ends[3], dateBuilder) || !isValidHour(tokens.starts[4], tokens.ends[4], dateBuilder) || !isValidMinuteSecond(tokens.starts[5], tokens.ends[5], dateBuilder, true) || !isValidMinuteSecond(tokens.starts[6], tokens.ends[6], dateBuilder, false)) {
            return null;
        }
        return dateBuilder.build();
    }

    private RFC2616Date buildANSICDate(Tokens tokens) {
        Builder dateBuilder = new Builder();
        if (!isValidMonth(tokens.starts[1], tokens.ends[1], dateBuilder) || !isValidDayOfMonth(tokens.starts[2], tokens.ends[2], dateBuilder) || !isValidHour(tokens.starts[3], tokens.ends[3], dateBuilder) || !isValidMinuteSecond(tokens.starts[4], tokens.ends[4], dateBuilder, true) || !isValidMinuteSecond(tokens.starts[5], tokens.ends[5], dateBuilder, false) || !isValidYear(tokens.starts[6], tokens.ends[6], dateBuilder)) {
            return null;
        }
        return dateBuilder.build();
    }

    private boolean isValid1DigitDayOfMonth(char c0, Builder dateBuilder) {
        if (!isDigit(c0)) {
            return false;
        }
        dateBuilder.setDayOfMonth(getNumericValue(c0));
        return true;
    }

    private boolean isValid2DigitsDayOfMonth(char c0, char c1, Builder dateBuilder) {
        if (isDigit(c0) && isDigit(c1)) {
            int day = (getNumericValue(c0) * 10) + getNumericValue(c1);
            if (day <= 31) {
                dateBuilder.setDayOfMonth(day);
                return true;
            }
        }
        return false;
    }

    private boolean isValidDayOfMonth(int start, int end, Builder dateBuilder) {
        int tokenLength = end - start;
        if (tokenLength == 1) {
            return isValid1DigitDayOfMonth(this.string.charAt(start), dateBuilder);
        }
        if (tokenLength == 2) {
            return isValid2DigitsDayOfMonth(this.string.charAt(start), this.string.charAt(start + 1), dateBuilder);
        }
        return false;
    }

    private boolean isValidJanuaryJuneJuly(char c0, char c1, char c2, Builder dateBuilder) {
        if (c0 == 'J' || c0 == 'j') {
            if (c1 == 'a' || c1 == 'A') {
                if (c2 == 'n' || c2 == 'N') {
                    dateBuilder.setJanuary();
                    return true;
                }
            } else if (c1 == 'u' || c1 == 'U') {
                if (c2 == 'n' || c2 == 'N') {
                    dateBuilder.setJune();
                    return true;
                } else if (c2 == 'l' || c2 == 'L') {
                    dateBuilder.setJuly();
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isValidFebruary(char c0, char c1, char c2, Builder dateBuilder) {
        if ((c0 != 'F' && c0 != 'f') || ((c1 != 'e' && c1 != 'E') || (c2 != 'b' && c2 != 'B'))) {
            return false;
        }
        dateBuilder.setFebruary();
        return true;
    }

    private boolean isValidMarchMay(char c0, char c1, char c2, Builder dateBuilder) {
        if ((c0 == 'M' || c0 == 'm') && (c1 == 'a' || c1 == 'A')) {
            if (c2 == 'r' || c2 == 'R') {
                dateBuilder.setMarch();
                return true;
            } else if (c2 == 'y' || c2 == 'M') {
                dateBuilder.setMay();
                return true;
            }
        }
        return false;
    }

    private boolean isValidAprilAugust(char c0, char c1, char c2, Builder dateBuilder) {
        if (c0 == 'A' || c0 == 'a') {
            if ((c1 == 'p' || c1 == 'P') && (c2 == 'r' || c2 == 'R')) {
                dateBuilder.setApril();
                return true;
            } else if ((c1 == 'u' || c1 == 'U') && (c2 == 'g' || c2 == 'G')) {
                dateBuilder.setAugust();
                return true;
            }
        }
        return false;
    }

    private boolean isValidSeptember(char c0, char c1, char c2, Builder dateBuilder) {
        if ((c0 != 'S' && c0 != 's') || ((c1 != 'e' && c1 != 'E') || (c2 != 'p' && c2 != 'P'))) {
            return false;
        }
        dateBuilder.setSeptember();
        return true;
    }

    private boolean isValidOctober(char c0, char c1, char c2, Builder dateBuilder) {
        if ((c0 != 'O' && c0 != 'o') || ((c1 != 'c' && c1 != 'C') || (c2 != 't' && c2 != 'T'))) {
            return false;
        }
        dateBuilder.setOctobre();
        return true;
    }

    private boolean isValidNovember(char c0, char c1, char c2, Builder dateBuilder) {
        if ((c0 != 'N' && c0 != 'n') || ((c1 != 'o' && c1 != 'O') || (c2 != 'v' && c2 != 'V'))) {
            return false;
        }
        dateBuilder.setNovembre();
        return true;
    }

    private boolean isValidDecember(char c0, char c1, char c2, Builder dateBuilder) {
        if ((c0 != 'D' && c0 != 'd') || ((c1 != 'e' && c1 != 'E') || (c2 != 'c' && c2 != 'C'))) {
            return false;
        }
        dateBuilder.setDecember();
        return true;
    }

    private boolean isValidMonth(int start, int end, Builder dateBuilder) {
        if (end - start != 3) {
            return false;
        }
        char c0 = this.string.charAt(start);
        char c1 = this.string.charAt(start + 1);
        char c2 = this.string.charAt(start + 2);
        if (isValidJanuaryJuneJuly(c0, c1, c2, dateBuilder) || isValidFebruary(c0, c1, c2, dateBuilder) || isValidMarchMay(c0, c1, c2, dateBuilder) || isValidAprilAugust(c0, c1, c2, dateBuilder) || isValidSeptember(c0, c1, c2, dateBuilder) || isValidOctober(c0, c1, c2, dateBuilder) || isValidNovember(c0, c1, c2, dateBuilder) || isValidDecember(c0, c1, c2, dateBuilder)) {
            return true;
        }
        return false;
    }

    private boolean isValid2DigitsYear(char c0, char c1, Builder dateBuilder) {
        if (!isDigit(c0) || !isDigit(c1)) {
            return false;
        }
        int year = (getNumericValue(c0) * 10) + getNumericValue(c1);
        return setValidYear(year < 70 ? year + 2000 : year + 1900, dateBuilder);
    }

    private boolean isValid4DigitsYear(char c0, char c1, char c2, char c3, Builder dateBuilder) {
        if (!isDigit(c0) || !isDigit(c1) || !isDigit(c2) || !isDigit(c3)) {
            return false;
        }
        return setValidYear((getNumericValue(c0) * 1000) + (getNumericValue(c1) * 100) + (getNumericValue(c2) * 10) + getNumericValue(c3), dateBuilder);
    }

    private boolean setValidYear(int year, Builder dateBuilder) {
        if (year < 1601) {
            return false;
        }
        dateBuilder.setYear(year);
        return true;
    }

    private boolean isValidYear(int start, int end, Builder dateBuilder) {
        int length2 = end - start;
        if (length2 == 2) {
            return isValid2DigitsYear(this.string.charAt(start), this.string.charAt(start + 1), dateBuilder);
        }
        if (length2 != 4) {
            return false;
        }
        return isValid4DigitsYear(this.string.charAt(start), this.string.charAt(start + 1), this.string.charAt(start + 2), this.string.charAt(start + 3), dateBuilder);
    }

    private boolean isValid1DigitHour(char c0, Builder dateBuilder) {
        if (!isDigit(c0)) {
            return false;
        }
        dateBuilder.setHour(getNumericValue(c0));
        return true;
    }

    private boolean isValid2DigitsHour(char c0, char c1, Builder dateBuilder) {
        if (isDigit(c0) && isDigit(c1)) {
            int hour = (getNumericValue(c0) * 10) + getNumericValue(c1);
            if (hour <= 24) {
                dateBuilder.setHour(hour);
                return true;
            }
        }
        return false;
    }

    private boolean isValidHour(int start, int end, Builder dateBuilder) {
        int length2 = end - start;
        if (length2 == 1) {
            return isValid1DigitHour(this.string.charAt(start), dateBuilder);
        }
        if (length2 == 2) {
            return isValid2DigitsHour(this.string.charAt(start), this.string.charAt(start + 1), dateBuilder);
        }
        return false;
    }

    private boolean isValid1DigitMinuteSecond(char c0, Builder dateBuilder, boolean minuteOrSecond) {
        if (!isDigit(c0)) {
            return false;
        }
        int value = getNumericValue(c0);
        if (minuteOrSecond) {
            dateBuilder.setMinute(value);
        } else {
            dateBuilder.setSecond(value);
        }
        return true;
    }

    private boolean isValid2DigitsMinuteSecond(char c0, char c1, Builder dateBuilder, boolean minuteOrSecond) {
        if (isDigit(c0) && isDigit(c1)) {
            int value = (getNumericValue(c0) * 10) + getNumericValue(c1);
            if (value <= 60) {
                if (minuteOrSecond) {
                    dateBuilder.setMinute(value);
                } else {
                    dateBuilder.setSecond(value);
                }
                return true;
            }
        }
        return false;
    }

    private boolean isValidMinuteSecond(int start, int end, Builder dateBuilder, boolean minuteOrSecond) {
        int length2 = end - start;
        if (length2 == 1) {
            return isValid1DigitMinuteSecond(this.string.charAt(start), dateBuilder, minuteOrSecond);
        }
        if (length2 == 2) {
            return isValid2DigitsMinuteSecond(this.string.charAt(start), this.string.charAt(start + 1), dateBuilder, minuteOrSecond);
        }
        return false;
    }

    private boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private int getNumericValue(char c) {
        return c - '0';
    }
}