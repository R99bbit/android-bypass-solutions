package org.acra;

import android.content.Context;
import com.embrain.panelbigdata.Vo.EmBasicResponse;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.util.Map.Entry;
import org.acra.collector.CrashReportData;

final class CrashReportPersister {
    private static final int CONTINUE = 3;
    private static final int IGNORE = 5;
    private static final int KEY_DONE = 4;
    private static final String LINE_SEPARATOR = "\n";
    private static final int NONE = 0;
    private static final int SLASH = 1;
    private static final int UNICODE = 2;
    private final Context context;

    CrashReportPersister(Context context2) {
        this.context = context2;
    }

    public CrashReportData load(String str) throws IOException {
        FileInputStream openFileInput = this.context.openFileInput(str);
        if (openFileInput != null) {
            try {
                BufferedInputStream bufferedInputStream = new BufferedInputStream(openFileInput, 8192);
                bufferedInputStream.mark(Integer.MAX_VALUE);
                boolean isEbcdic = isEbcdic(bufferedInputStream);
                bufferedInputStream.reset();
                if (!isEbcdic) {
                    return load((Reader) new InputStreamReader(bufferedInputStream, "ISO8859-1"));
                }
                CrashReportData load = load((Reader) new InputStreamReader(bufferedInputStream));
                openFileInput.close();
                return load;
            } finally {
                openFileInput.close();
            }
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("Invalid crash report fileName : ");
            sb.append(str);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    public void store(CrashReportData crashReportData, String str) throws IOException {
        FileOutputStream openFileOutput = this.context.openFileOutput(str, 0);
        try {
            StringBuilder sb = new StringBuilder(EmBasicResponse.CODE_SUCCESS);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(openFileOutput, "ISO8859_1");
            for (Entry entry : crashReportData.entrySet()) {
                dumpString(sb, ((ReportField) entry.getKey()).toString(), true);
                sb.append('=');
                dumpString(sb, (String) entry.getValue(), false);
                sb.append(LINE_SEPARATOR);
                outputStreamWriter.write(sb.toString());
                sb.setLength(0);
            }
            outputStreamWriter.flush();
        } finally {
            openFileOutput.close();
        }
    }

    private boolean isEbcdic(BufferedInputStream bufferedInputStream) throws IOException {
        byte read;
        do {
            read = (byte) bufferedInputStream.read();
            if (read == -1 || read == 35 || read == 10 || read == 61) {
                return false;
            }
        } while (read != 21);
        return true;
    }

    /* JADX WARNING: Removed duplicated region for block: B:123:0x0155  */
    /* JADX WARNING: Removed duplicated region for block: B:124:0x0158  */
    private synchronized CrashReportData load(Reader reader) throws IOException {
        CrashReportData crashReportData;
        char c;
        int i;
        char c2;
        char c3;
        char c4;
        char c5;
        char c6;
        crashReportData = new CrashReportData();
        BufferedReader bufferedReader = new BufferedReader(reader, 8192);
        char c7 = 2;
        char c8 = 1;
        int i2 = 0;
        char[] cArr = new char[40];
        int i3 = 0;
        char c9 = 0;
        int i4 = 0;
        int i5 = -1;
        int i6 = 0;
        while (true) {
            boolean z = true;
            while (true) {
                int read = bufferedReader.read();
                if (read == -1) {
                    if (c == c2) {
                        if (i4 <= 4) {
                            throw new IllegalArgumentException("luni.08");
                        }
                    }
                    if (i5 == -1 && i3 > 0) {
                        i5 = i3;
                    }
                    if (i5 >= 0) {
                        String str = new String(cArr, i, i3);
                        ReportField reportField = (ReportField) Enum.valueOf(ReportField.class, str.substring(i, i5));
                        String substring = str.substring(i5);
                        if (c == c8) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(substring);
                            sb.append("\u0000");
                            substring = sb.toString();
                        }
                        crashReportData.put(reportField, substring);
                    }
                } else {
                    char c10 = (char) read;
                    if (i3 == cArr.length) {
                        char[] cArr2 = new char[(cArr.length * 2)];
                        System.arraycopy(cArr, i, cArr2, i, i3);
                        cArr = cArr2;
                    }
                    if (c == c2) {
                        int digit = Character.digit(c10, 16);
                        if (digit >= 0) {
                            i6 = (i6 << 4) + digit;
                            i4++;
                            if (i4 < 4) {
                                c5 = 2;
                                i = 0;
                            }
                        } else if (i4 <= 4) {
                            throw new IllegalArgumentException("luni.09");
                        }
                        int i7 = i3 + 1;
                        cArr[i3] = (char) i6;
                        if (c10 == 10 || c10 == 133) {
                            i3 = i7;
                            c = 0;
                        } else {
                            i3 = i7;
                            c2 = 2;
                            i = 0;
                            c = 0;
                        }
                    }
                    if (c != c8) {
                        if (c10 == 10) {
                            if (c != 3) {
                                break;
                            }
                            c4 = 2;
                            c8 = 1;
                            i = 0;
                            c = 5;
                        } else if (c10 == 13) {
                            break;
                        } else {
                            if (c10 == '!' || c10 == '#') {
                                if (z) {
                                    while (true) {
                                        int read2 = bufferedReader.read();
                                        if (read2 != -1) {
                                            char c11 = (char) read2;
                                            if (c11 != 13 && c11 != 10) {
                                                if (c11 == 133) {
                                                    break;
                                                }
                                            } else {
                                                break;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                    c5 = 2;
                                    c8 = 1;
                                    i = 0;
                                }
                            } else if (c10 == ':' || c10 == '=') {
                                if (i5 == -1) {
                                    i5 = i3;
                                    c2 = 2;
                                    c8 = 1;
                                    i = 0;
                                    c = 0;
                                }
                            } else if (c10 != '\\') {
                                if (c10 == 133) {
                                    break;
                                }
                            } else {
                                if (c == 4) {
                                    i5 = i3;
                                }
                                c2 = 2;
                                c8 = 1;
                                i = 0;
                                c = 1;
                            }
                            if (Character.isWhitespace(c10)) {
                                if (c == 3) {
                                    c = 5;
                                }
                                if (i3 == 0 || i3 == i5) {
                                    c5 = 2;
                                    c8 = 1;
                                    i = 0;
                                } else {
                                    c6 = 5;
                                    if (c == 5) {
                                        c5 = 2;
                                        c8 = 1;
                                        i = 0;
                                    } else if (i5 == -1) {
                                        c2 = 2;
                                        c8 = 1;
                                        i = 0;
                                        c = 4;
                                    }
                                }
                            } else {
                                c6 = 5;
                            }
                            c3 = c;
                            if (c3 != c6) {
                                if (c3 == 3) {
                                }
                                if (c3 != 4) {
                                    i5 = i3;
                                    c = 0;
                                } else {
                                    c = c3;
                                }
                                cArr[i3] = c10;
                                i3++;
                                c2 = 2;
                                c8 = 1;
                                i = 0;
                                z = false;
                            }
                        }
                    } else {
                        if (c10 != 10) {
                            if (c10 == 13) {
                                c2 = 2;
                                i = 0;
                                c = 3;
                            } else if (c10 == 'b') {
                                c10 = 8;
                            } else if (c10 == 'f') {
                                c10 = 12;
                            } else if (c10 == 'n') {
                                c10 = 10;
                            } else if (c10 == 'r') {
                                c10 = 13;
                            } else if (c10 != 133) {
                                if (c10 == 't') {
                                    c10 = 9;
                                } else if (c10 == 'u') {
                                    c2 = 2;
                                    i = 0;
                                    c = 2;
                                    i4 = 0;
                                    i6 = 0;
                                }
                            }
                        }
                        c4 = 2;
                        i = 0;
                        c = 5;
                    }
                    c3 = 0;
                    if (c3 != 4) {
                    }
                    cArr[i3] = c10;
                    i3++;
                    c2 = 2;
                    c8 = 1;
                    i = 0;
                    z = false;
                }
            }
            if (i3 <= 0) {
                if (i3 != 0 || i5 != 0) {
                    i3 = 0;
                    c7 = 2;
                    c8 = 1;
                    i2 = 0;
                    c9 = 0;
                    i5 = -1;
                }
            }
            if (i5 == -1) {
                i5 = i3;
            }
            String str2 = new String(cArr, 0, i3);
            crashReportData.put(Enum.valueOf(ReportField.class, str2.substring(0, i5)), str2.substring(i5));
            i3 = 0;
            c7 = 2;
            c8 = 1;
            i2 = 0;
            c9 = 0;
            i5 = -1;
        }
        return crashReportData;
    }

    private void dumpString(StringBuilder sb, String str, boolean z) {
        int i;
        if (z || str.length() <= 0 || str.charAt(0) != ' ') {
            i = 0;
        } else {
            sb.append("\\ ");
            i = 1;
        }
        while (i < str.length()) {
            char charAt = str.charAt(i);
            switch (charAt) {
                case 9:
                    sb.append("\\t");
                    break;
                case 10:
                    sb.append("\\n");
                    break;
                case 12:
                    sb.append("\\f");
                    break;
                case 13:
                    sb.append("\\r");
                    break;
                default:
                    if ("\\#!=:".indexOf(charAt) >= 0 || (z && charAt == ' ')) {
                        sb.append('\\');
                    }
                    if (charAt >= ' ' && charAt <= '~') {
                        sb.append(charAt);
                        break;
                    } else {
                        String hexString = Integer.toHexString(charAt);
                        sb.append("\\u");
                        for (int i2 = 0; i2 < 4 - hexString.length(); i2++) {
                            sb.append("0");
                        }
                        sb.append(hexString);
                        break;
                    }
                    break;
            }
            i++;
        }
    }
}