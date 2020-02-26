package co.habitfactory.signalfinance_embrain.comm;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.database.SQLException;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.os.Build;
import android.os.Build.VERSION;
import android.telephony.TelephonyManager;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.util.Xml;
import android.widget.TextView;
import co.habitfactory.signalfinance_embrain.dataset.FinanceInfoDataSet;
import co.habitfactory.signalfinance_embrain.dataset.SmsReceiveNumberSet;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperFinanceInfo;
import co.habitfactory.signalfinance_embrain.db.DatabaseHelperSmsReceiveNumber;
import com.embrain.panelpower.IConstValue.UserConst;
import com.kakao.network.ServerProtocol;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.sql.Timestamp;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.TimeZone;
import org.xmlpull.v1.XmlSerializer;

public class SignalUtil implements SignalLibConsts {
    private static final String TAG = "SignalUtil";
    public static boolean isShowLog = false;

    public static boolean isMissedDataAlarmOn(Context context) throws Exception {
        return PendingIntent.getBroadcast(context, SignalLibConsts.MISSINGDATA_CHECK_ALARM_CODE, new Intent(SignalLibConsts.INTENT_MISSINGDATA_CHECK_ALARM_ACTION), 536870912) != null;
    }

    public static boolean isAppListDataAlarmOn(Context context) throws Exception {
        return PendingIntent.getBroadcast(context, SignalLibConsts.APPSLIST_ALARM_CODE, new Intent(SignalLibConsts.INTENT_APPSLIST_ALARM_ACTION), 536870912) != null;
    }

    public static void PRINT_LOG(String str, String str2) {
        if (isShowLog) {
            if (str == null || str.length() == 0) {
                str = "SIGNAL";
            }
            if (str2 != null) {
                try {
                    if (str2.length() > 4000) {
                        int length = str2.length() / 4000;
                        int i = 0;
                        while (i < length) {
                            int i2 = i + 1;
                            int i3 = 4000 * i2;
                            if (i3 >= str2.length()) {
                                Log.d(str, str2.substring(i * 4000));
                            } else {
                                Log.d(str, str2.substring(i * 4000, i3));
                            }
                            i = i2;
                        }
                    } else {
                        Log.d(str, str2);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void setTextViewColorPartial(TextView textView, String str, String str2, int i) {
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(str);
        try {
            int indexOf = str.indexOf(str2);
            spannableStringBuilder.setSpan(new ForegroundColorSpan(i), indexOf, str2.length() + indexOf, 33);
            textView.append(spannableStringBuilder);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String createXml(HashMap<String, String> hashMap) {
        XmlSerializer newSerializer = Xml.newSerializer();
        StringWriter stringWriter = new StringWriter();
        try {
            newSerializer.setOutput(stringWriter);
            for (String next : hashMap.keySet()) {
                String str = "";
                try {
                    str = URLEncoder.encode(hashMap.get(next), "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
                newSerializer.startTag(null, next);
                newSerializer.text(str);
                newSerializer.endTag(null, next);
            }
            newSerializer.endDocument();
            return stringWriter.toString();
        } catch (Exception e2) {
            e2.printStackTrace();
            return UserConst.GENDER_NOT;
        }
    }

    public static String createXml(HashMap<String, String> hashMap, Boolean bool) {
        XmlSerializer newSerializer = Xml.newSerializer();
        StringWriter stringWriter = new StringWriter();
        try {
            newSerializer.setOutput(stringWriter);
            for (String next : hashMap.keySet()) {
                String str = "";
                if (bool.booleanValue()) {
                    try {
                        str = URLEncoder.encode(hashMap.get(next), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                } else {
                    str = hashMap.get(next);
                }
                newSerializer.startTag(null, next);
                newSerializer.text(str);
                newSerializer.endTag(null, next);
            }
            newSerializer.endDocument();
            return stringWriter.toString();
        } catch (Exception e2) {
            e2.printStackTrace();
            return UserConst.GENDER_NOT;
        }
    }

    public static synchronized String createXml(ArrayList<HashMap<String, String>> arrayList, String str) {
        String str2;
        synchronized (SignalUtil.class) {
            str2 = "";
            Iterator<HashMap<String, String>> it = arrayList.iterator();
            while (it.hasNext()) {
                HashMap next = it.next();
                if (!UserConst.GENDER_NOT.equals(createXml(next, str))) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(str2);
                    sb.append(createXml(next, str));
                    str2 = sb.toString();
                }
            }
        }
        return str2;
    }

    public static String createXml(HashMap<String, String> hashMap, String str) {
        XmlSerializer newSerializer = Xml.newSerializer();
        StringWriter stringWriter = new StringWriter();
        try {
            newSerializer.setOutput(stringWriter);
            newSerializer.startTag(null, str);
            for (String next : hashMap.keySet()) {
                String str2 = "";
                try {
                    str2 = URLEncoder.encode(hashMap.get(next), "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
                newSerializer.startTag(null, next);
                newSerializer.text(str2);
                newSerializer.endTag(null, next);
            }
            newSerializer.endTag(null, str);
            newSerializer.endDocument();
            return stringWriter.toString();
        } catch (Exception e2) {
            e2.printStackTrace();
            return UserConst.GENDER_NOT;
        }
    }

    public static String createXml(HashMap<String, String> hashMap, String str, Boolean bool) {
        XmlSerializer newSerializer = Xml.newSerializer();
        StringWriter stringWriter = new StringWriter();
        try {
            newSerializer.setOutput(stringWriter);
            newSerializer.startTag(null, str);
            for (String next : hashMap.keySet()) {
                String str2 = "";
                if (bool.booleanValue()) {
                    try {
                        str2 = URLEncoder.encode(hashMap.get(next), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                } else {
                    str2 = hashMap.get(next);
                }
                newSerializer.startTag(null, next);
                newSerializer.text(str2);
                newSerializer.endTag(null, next);
            }
            newSerializer.endTag(null, str);
            newSerializer.endDocument();
            return stringWriter.toString();
        } catch (Exception e2) {
            e2.printStackTrace();
            return UserConst.GENDER_NOT;
        }
    }

    public static Boolean isNetworkConnect(Context context) throws Exception {
        if (NetWork.isMOBILEConnected(context) || NetWork.isWIFIConnected(context)) {
            return Boolean.valueOf(true);
        }
        return Boolean.valueOf(false);
    }

    public static byte[] getBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] bArr = new byte[1024];
        while (true) {
            int read = inputStream.read(bArr);
            if (read == -1) {
                return byteArrayOutputStream.toByteArray();
            }
            byteArrayOutputStream.write(bArr, 0, read);
        }
    }

    public static String getCurrentTime(String str) {
        if (str == null || str.length() == 0) {
            str = "yyyyMMddHHmmss";
        }
        return new SimpleDateFormat(str).format(new Date(System.currentTimeMillis()));
    }

    public static String getCurrentTime(String str, String str2) {
        if (str == null || str.length() == 0) {
            str = "yyyyMMddHHmmss";
        }
        if (str2 != null) {
            int length = str2.length();
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str);
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("Asia/Seoul"));
        return simpleDateFormat.format(new Date(System.currentTimeMillis()));
    }

    public static String getCurrentTime(String str, long j) {
        if (str == null || str.length() == 0) {
            str = "yyyyMMddHHmmss";
        }
        return new SimpleDateFormat(str).format(new Date(j));
    }

    public static String getPreviousDate(String str, String str2) {
        Date date;
        try {
            date = new SimpleDateFormat("yyyyMMdd", Locale.KOREA).parse(str2);
        } catch (ParseException e) {
            e.printStackTrace();
            date = null;
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str);
        Calendar instance = Calendar.getInstance();
        instance.setTime(date);
        instance.add(5, -1);
        return simpleDateFormat.format(instance.getTime());
    }

    public static String getPreviousDateFromSetDay(String str, String str2, int i) {
        Date date;
        try {
            date = new SimpleDateFormat("yyyyMMdd", Locale.KOREA).parse(str2);
        } catch (ParseException e) {
            e.printStackTrace();
            date = null;
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str);
        Calendar instance = Calendar.getInstance();
        instance.setTime(date);
        instance.add(5, -i);
        return simpleDateFormat.format(instance.getTime());
    }

    public static String getBeforOrNextMonthByYM(String str, int i, int i2) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMM");
        Calendar instance = Calendar.getInstance();
        int parseInt = Integer.parseInt(str.substring(0, 4));
        int parseInt2 = Integer.parseInt(str.substring(4, 6));
        if (i2 == 0) {
            instance.set(parseInt, parseInt2 - i, 0);
        } else {
            instance.set(parseInt, parseInt2 + i, 0);
        }
        String substring = simpleDateFormat.format(instance.getTime()).substring(0, 4);
        String substring2 = simpleDateFormat.format(instance.getTime()).substring(4, 6);
        StringBuilder sb = new StringBuilder();
        sb.append(substring);
        sb.append(substring2);
        return sb.toString();
    }

    public static String getNextMonth(String str, String str2) {
        Date date;
        try {
            date = new SimpleDateFormat("yyyyMMdd", Locale.KOREA).parse(str2);
        } catch (ParseException e) {
            e.printStackTrace();
            date = null;
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str);
        Calendar instance = Calendar.getInstance();
        instance.setTime(date);
        instance.add(2, 1);
        return simpleDateFormat.format(instance.getTime());
    }

    public static String changeDateFormat(String str) {
        return changeDateFormat(str, null);
    }

    public static String changeDateFormat(String str, String str2) {
        if (str2 == null || str2.length() == 0) {
            str2 = "yyyy-MM-dd";
        }
        Calendar instance = Calendar.getInstance();
        try {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str2, Locale.KOREA);
            instance.setTime(simpleDateFormat.parse(str));
            return simpleDateFormat.format(instance.getTime());
        } catch (ParseException e) {
            e.printStackTrace();
            return str;
        }
    }

    public static String changeDateFormatFromDate(Date date, String str) {
        if (str == null || str.length() == 0) {
            str = "yyyy-MM-dd";
        }
        Calendar instance = Calendar.getInstance();
        try {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(str, Locale.KOREA);
            instance.setTime(date);
            return simpleDateFormat.format(instance.getTime());
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String timeStampToDate(String str) {
        Date date;
        try {
            date = new SimpleDateFormat("yyyyMMddHHmmss").parse(str);
        } catch (ParseException e) {
            e.printStackTrace();
            date = null;
        }
        try {
            return new SimpleDateFormat("yyyy-MM-dd", Locale.KOREA).format(Long.valueOf(date.getTime()));
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public static String changeDateFormat(String str, String str2, String str3) {
        if (str3 == null || str3.length() == 0) {
            str3 = "yyyy-MM-dd";
        }
        try {
            return new SimpleDateFormat(str3, Locale.KOREA).format(Long.valueOf(new SimpleDateFormat(str2, Locale.KOREA).parse(str).getTime()));
        } catch (ParseException e) {
            e.printStackTrace();
            return str;
        }
    }

    public static String makeMoneyComma(String str) {
        if (str == null || str.length() <= 0) {
            return "";
        }
        try {
            str = new DecimalFormat("###,###.####").format(Double.parseDouble(str.replaceAll(",", "")));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    public static String todayDateyyyyMMdd() {
        return new SimpleDateFormat("yyyy.MM.dd", Locale.KOREA).format(new Date());
    }

    public static boolean isRunningProcess(Context context, String str) {
        for (RunningAppProcessInfo runningAppProcessInfo : ((ActivityManager) context.getSystemService("activity")).getRunningAppProcesses()) {
            if (runningAppProcessInfo.processName.equals(str)) {
                return true;
            }
        }
        return false;
    }

    public static String NULL_TO_STRING(String str) {
        if (str != null) {
            try {
                if (str.length() != 0 && !"null".equals(str)) {
                    return str;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return str;
            }
        }
        return "";
    }

    public static String NULL_TO_DASH(String str) {
        if (str != null) {
            try {
                if (str.length() != 0) {
                    return str;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return str;
            }
        }
        return "-";
    }

    public static String getOperatorName(Context context) {
        return ((TelephonyManager) context.getSystemService("phone")).getNetworkOperatorName();
    }

    public static String getCountrylso(Context context) {
        return ((TelephonyManager) context.getSystemService("phone")).getSimCountryIso();
    }

    public static boolean getRoamingState(Context context) {
        return ((TelephonyManager) context.getSystemService("phone")).isNetworkRoaming();
    }

    public static Bitmap getBitmapFromURL(String str) {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(str).openConnection();
            httpURLConnection.setDoInput(true);
            httpURLConnection.connect();
            return BitmapFactory.decodeStream(httpURLConnection.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String addCommaSign(String str) {
        String str2 = "0";
        if (str != null && !str.trim().equals("")) {
            String replace = str.replace("+", "").replace(",", "");
            if (!isNumeric(replace)) {
                return str2;
            }
            try {
                str2 = new DecimalFormat("###,###,###,###,###.########").format(Double.parseDouble(replace));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return str2;
    }

    public static String getNumberWithoutComma(String str) {
        if (str == null || str.length() == 0) {
            return "0";
        }
        String trim = str.toString().trim();
        if (!trim.contains(",")) {
            return trim;
        }
        try {
            return trim.replace(",", "");
        } catch (Exception e) {
            e.printStackTrace();
            return "0";
        }
    }

    public static int getResId(String str, Class<?> cls) {
        try {
            Field declaredField = cls.getDeclaredField(str);
            return declaredField.getInt(declaredField);
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    public static boolean isNumeric(String str) {
        if (str == null || str.length() == 0) {
            return false;
        }
        return str.matches("-?\\d+(\\.\\d+)?");
    }

    public static void validateStoreName(TextView textView, String str) {
        if (str == null || str.length() == 0) {
            textView.setText("(\uc810\ud3ec\uba85\uc774 \uc5c6\uc2b5\ub2c8\ub2e4.)");
            textView.setTypeface(null, 2);
            return;
        }
        textView.setText(str);
    }

    public static void validateAccountComanyName(TextView textView, String str) {
        if (str == null || str.length() == 0) {
            textView.setText("(\uc815\ubcf4\uc5c6\uc74c)");
            textView.setTextColor(Color.parseColor("#888888"));
            return;
        }
        textView.setText(str);
    }

    public static String changeCardUsageTypeCodetoName(String str) {
        if (str.length() > 0) {
            if ("PCT".equals(str)) {
                return "[\uc2e0\uc6a9]";
            }
            if ("PCK".equals(str)) {
                return "[\uccb4\ud06c]";
            }
            if ("CCT".equals(str)) {
                return "[\ubc95\uc778 \uc2e0\uc6a9]";
            }
            if ("CCK".equals(str)) {
                return "[\ubc95\uc778 \uccb4\ud06c]";
            }
            if ("PBK".equals(str)) {
                return "[\ud1b5\uc7a5]";
            }
            if ("PBK".equals(str)) {
                return "[\ubc95\uc778 \ud1b5\uc7a5]";
            }
            if ("PCS".equals(str)) {
                return "[\ud604\uae08]";
            }
        }
        return "";
    }

    public static Timestamp convertToTimestamp(String str) {
        if (str == null) {
            return null;
        }
        try {
            if (str.trim().equals("")) {
                return null;
            }
            String substring = str.substring(0, 4);
            String substring2 = str.substring(4, 6);
            int parseInt = Integer.parseInt(str.substring(6, 8));
            GregorianCalendar gregorianCalendar = new GregorianCalendar();
            gregorianCalendar.set(Integer.parseInt(substring), Integer.parseInt(substring2) - 1, parseInt);
            gregorianCalendar.getTime();
            return new Timestamp(gregorianCalendar.getTime().getTime());
        } catch (NumberFormatException e) {
            e.printStackTrace();
            return null;
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public static String convertTime(String str) {
        if (str == null || str.length() <= 0 || str.length() < 4) {
            return "";
        }
        try {
            String substring = str.substring(0, 2);
            String substring2 = str.substring(2, 4);
            StringBuilder sb = new StringBuilder();
            sb.append(substring);
            sb.append(":");
            sb.append(substring2);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static int getCurrentDayofWeek() {
        try {
            return Calendar.getInstance().get(7);
        } catch (Exception e) {
            e.printStackTrace();
            return 1;
        }
    }

    public static String getDateDay(String str, String str2) throws Exception {
        String str3;
        Date parse = new SimpleDateFormat(str2).parse(str);
        Calendar instance = Calendar.getInstance();
        instance.setTime(parse);
        switch (instance.get(7)) {
            case 1:
                str3 = "\uc77c";
                break;
            case 2:
                str3 = "\uc6d4";
                break;
            case 3:
                str3 = "\ud654";
                break;
            case 4:
                str3 = "\uc218";
                break;
            case 5:
                str3 = "\ubaa9";
                break;
            case 6:
                str3 = "\uae08";
                break;
            case 7:
                str3 = "\ud1a0";
                break;
            default:
                str3 = "";
                break;
        }
        String changeDateFormatFromDate = changeDateFormatFromDate(parse, "yyyy.MM.dd");
        StringBuilder sb = new StringBuilder();
        sb.append(changeDateFormatFromDate);
        sb.append("(");
        sb.append(str3);
        sb.append(")");
        return sb.toString();
    }

    public static String getDateDayForEnglish(String str, String str2) throws Exception {
        Date parse = new SimpleDateFormat(str2).parse(str);
        Calendar instance = Calendar.getInstance();
        instance.setTime(parse);
        switch (instance.get(7)) {
            case 1:
                return "SUNDAY";
            case 2:
                return "MONDAY";
            case 3:
                return "TUESDAY";
            case 4:
                return "WEDNESDAY";
            case 5:
                return "THURSDAY";
            case 6:
                return "FRIDAY";
            case 7:
                return "SATURDAY";
            default:
                return "";
        }
    }

    public static boolean isBrokenSamsungDevice() {
        return Build.MANUFACTURER.equalsIgnoreCase("samsung") && isBetweenAndroidVersions(21, 22);
    }

    public static boolean isBetweenAndroidVersions(int i, int i2) {
        return VERSION.SDK_INT >= i && VERSION.SDK_INT <= i2;
    }

    /* JADX WARNING: Removed duplicated region for block: B:15:0x0023 A[SYNTHETIC, Splitter:B:15:0x0023] */
    /* JADX WARNING: Removed duplicated region for block: B:39:? A[RETURN, SYNTHETIC] */
    public static String convertDateSlashtoText(String str) {
        String str2;
        if (str == null || str.length() <= 0) {
            return str;
        }
        String str3 = null;
        try {
            String[] split = str.split("/");
            str2 = split[0];
            try {
                str3 = split[1];
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
            str2 = str3;
            e.printStackTrace();
            if (str2 != null) {
            }
        }
        if (str2 != null) {
            return str;
        }
        try {
            if (str2.length() <= 0) {
                return str;
            }
            if (str2.startsWith("0")) {
                str2 = str2.replace("0", "");
            }
            if (str3 == null) {
                return str;
            }
            try {
                if (str3.length() <= 0) {
                    return str;
                }
                if (str3.startsWith("0")) {
                    str3 = str2.replace("0", "");
                }
                if (str2 == null || str3 == null) {
                    return str;
                }
                StringBuilder sb = new StringBuilder();
                sb.append(str2);
                sb.append("\uc6d4");
                sb.append(str3);
                sb.append("\uc77c");
                return sb.toString();
            } catch (Exception e3) {
                e3.printStackTrace();
            }
        } catch (Exception e4) {
            e4.printStackTrace();
        }
    }

    public static int getAgeFromBirthday(String str) {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.setTime(new Date());
        if (isNumeric(str)) {
            return gregorianCalendar.get(1) - Integer.parseInt(str);
        }
        return 0;
    }

    public static String changeCardcdToCardname(String str) {
        if ("BC".equals(str)) {
            return "\ube44\uc528";
        }
        if ("CT".equals(str)) {
            return "\uc528\ud2f0";
        }
        if ("DG".equals(str)) {
            return "\ub300\uad6c";
        }
        if ("HD".equals(str)) {
            return "\ud604\ub300";
        }
        if ("HN".equals(str)) {
            return "\ud558\ub098";
        }
        if ("HS".equals(str)) {
            return "\ud604\ub300\uc99d\uad8c";
        }
        if ("IB".equals(str)) {
            return "\uae30\uc5c5";
        }
        if ("JE".equals(str)) {
            return "\uc81c\uc8fc";
        }
        if ("KB".equals(str)) {
            return "\uad6d\ubbfc";
        }
        if ("KD".equals(str)) {
            return "\uc0b0\uc5c5";
        }
        if ("KE".equals(str)) {
            return "\uc678\ud658";
        }
        if ("KJ".equals(str)) {
            return "\uad11\uc8fc";
        }
        if ("LO".equals(str)) {
            return "\ub86f\ub370";
        }
        if ("MG".equals(str)) {
            return "\uc0c8\ub9c8\uc744\uae08\uace0";
        }
        if ("NH".equals(str)) {
            return "\ub18d\ud611";
        }
        if ("PO".equals(str)) {
            return "\uc6b0\uccb4\uad6d";
        }
        if ("PU".equals(str)) {
            return "\ubd80\uc0b0";
        }
        if ("SC".equals(str)) {
            return "SC";
        }
        if ("SH".equals(str)) {
            return "\uc2e0\ud55c";
        }
        if ("SS".equals(str)) {
            return "\uc0bc\uc131";
        }
        if ("SU".equals(str)) {
            return "\uc218\ud611";
        }
        if ("WR".equals(str)) {
            return "\uc6b0\ub9ac";
        }
        return "CS".equals(str) ? "\ud604\uae08" : "";
    }

    public static String getServerUrl(Context context) {
        String str;
        SignalLibPrefs signalLibPrefs = new SignalLibPrefs(context);
        String string = signalLibPrefs.getString(SignalLibConsts.PREF_API_SERVER_URL);
        if (string != null) {
            try {
                if (!string.equals("")) {
                    return string;
                }
            } catch (Exception unused) {
                return string;
            }
        }
        try {
            str = (String) context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData.get("API_SERVER_URL");
            try {
                if (str.length() > 0) {
                    signalLibPrefs.putString(SignalLibConsts.PREF_API_SERVER_URL, str.trim());
                    return str;
                }
            } catch (Exception e) {
                e = e;
                string = str;
                e.printStackTrace();
                str = string;
                return str;
            }
        } catch (Exception e2) {
            e = e2;
            e.printStackTrace();
            str = string;
            return str;
        }
        return str;
    }

    public static String getNetworkOperatorName(Context context) {
        try {
            String string = new SignalLibPrefs(context).getString(SignalLibConsts.PREF_API_USER_NETWORK_OPERATOR_NAME);
            if (string != null || string.length() > 0) {
            }
            return string;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getUserId(Context context) {
        String string = new SignalLibPrefs(context).getString(SignalLibConsts.PREF_API_USER_USERID);
        if (string != null) {
            try {
                if (string.equals("") || "null".equals(string)) {
                    return "";
                }
                return string;
            } catch (Exception unused) {
                return string;
            }
        }
        return "";
    }

    public static String getDeviceLineNumber(Context context) {
        try {
            String string = new SignalLibPrefs(context).getString(SignalLibConsts.PREF_API_USER_PNUMBER);
            if (string != null || string.length() > 0) {
            }
            return string;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String reviseSmsMessage(String str) {
        if (str != null) {
            try {
                if (str.length() > 0) {
                    return str.trim().replaceAll("[%]", "<!per!>").replaceAll("[+]", "<!plus!>");
                }
            } catch (Exception e) {
                e.printStackTrace();
                return str;
            }
        }
        return "";
    }

    public static String getDeviceNumberTakeTill(Context context) throws Exception {
        String deviceLineNumber;
        int i = 0;
        while (true) {
            try {
                deviceLineNumber = getDeviceLineNumber(context);
                if (deviceLineNumber.length() > 0) {
                    break;
                }
                Thread.sleep(1000);
                i++;
                if (i > 5) {
                    break;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return deviceLineNumber;
    }

    public static String getTimemillisFirstDay(String str) throws Exception {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMM");
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(str);
            sb.append("000");
            String format = simpleDateFormat.format(new Date(Long.valueOf(sb.toString()).longValue()));
            StringBuilder sb2 = new StringBuilder();
            sb2.append(format);
            sb2.append("01000000");
            return date2TimeStamp(sb2.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return str;
        }
    }

    public static String date2TimeStamp(String str) {
        try {
            return String.valueOf(new SimpleDateFormat("yyyyMMddHHmmss").parse(str).getTime() / 1000);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getCurrentTimestamp() {
        String str;
        Calendar instance = Calendar.getInstance();
        instance.get(6);
        try {
            str = String.valueOf(instance.getTimeInMillis());
        } catch (Exception e) {
            e.printStackTrace();
            str = "";
        }
        if (str != null) {
        }
        return str;
    }

    public static void getAssetData(int i, Context context) throws Exception {
        String str = TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("type : ");
        sb.append(i);
        PRINT_LOG(str, sb.toString());
        int i2 = 0;
        if (i == 1) {
            String loadAssetTextAsString = loadAssetTextAsString(context, "getNum.txt");
            if (loadAssetTextAsString.length() > 0) {
                try {
                    String[] split = loadAssetTextAsString.split("\n");
                    if (split.length > 0) {
                        DatabaseHelperSmsReceiveNumber instance = DatabaseHelperSmsReceiveNumber.getInstance(context);
                        instance.onCreateWithTable(instance.getDB(), DatabaseHelperSmsReceiveNumber.TABLE_NAME);
                        ArrayList arrayList = new ArrayList();
                        while (i2 < split.length) {
                            arrayList.add(new SmsReceiveNumberSet(split[i2], "", "C"));
                            i2++;
                        }
                        instance.addRowList(arrayList);
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        } else if (i == 2) {
            String loadAssetTextAsString2 = loadAssetTextAsString(context, "getPname.txt");
            if (loadAssetTextAsString2.length() > 0) {
                try {
                    String[] split2 = loadAssetTextAsString2.split("\n");
                    if (split2.length > 0) {
                        DatabaseHelperFinanceInfo instance2 = DatabaseHelperFinanceInfo.getInstance(context);
                        instance2.onCreateWithTable(instance2.getDB(), DatabaseHelperFinanceInfo.TABLE_NAME);
                        int i3 = 0;
                        while (i2 < split2.length) {
                            try {
                                instance2.addRow(new FinanceInfoDataSet("", split2[i2].toString()));
                                i3++;
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                            i2++;
                        }
                        String str2 = TAG;
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("packageNmArray.size : ");
                        sb2.append(i3);
                        PRINT_LOG(str2, sb2.toString());
                    }
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
            }
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:24:0x0044 A[SYNTHETIC, Splitter:B:24:0x0044] */
    /* JADX WARNING: Removed duplicated region for block: B:32:0x0051 A[SYNTHETIC, Splitter:B:32:0x0051] */
    private static String loadAssetTextAsString(Context context, String str) {
        BufferedReader bufferedReader;
        BufferedReader bufferedReader2 = null;
        try {
            StringBuilder sb = new StringBuilder();
            bufferedReader = new BufferedReader(new InputStreamReader(context.getAssets().open(str)));
            boolean z = true;
            while (true) {
                try {
                    String readLine = bufferedReader.readLine();
                    if (readLine == null) {
                        break;
                    }
                    if (z) {
                        z = false;
                    } else {
                        sb.append(10);
                    }
                    sb.append(readLine);
                } catch (IOException e) {
                    e = e;
                    try {
                        e.printStackTrace();
                        if (bufferedReader != null) {
                            try {
                                bufferedReader.close();
                            } catch (IOException e2) {
                                e2.printStackTrace();
                            }
                        }
                        return null;
                    } catch (Throwable th) {
                        th = th;
                        bufferedReader2 = bufferedReader;
                        if (bufferedReader2 != null) {
                        }
                        throw th;
                    }
                }
            }
            String sb2 = sb.toString();
            try {
                bufferedReader.close();
            } catch (IOException e3) {
                e3.printStackTrace();
            }
            return sb2;
        } catch (IOException e4) {
            e = e4;
            bufferedReader = null;
            e.printStackTrace();
            if (bufferedReader != null) {
            }
            return null;
        } catch (Throwable th2) {
            th = th2;
            if (bufferedReader2 != null) {
                try {
                    bufferedReader2.close();
                } catch (IOException e5) {
                    e5.printStackTrace();
                }
            }
            throw th;
        }
    }

    public static String reviseSmsMessage2(String str) {
        if (str != null) {
            try {
                if (str.length() > 0) {
                    String replaceAll = str.trim().replaceAll("\\r\\n|\\r|\\n", ServerProtocol.AUTHORIZATION_HEADER_DELIMITER).replaceAll("\\t", ServerProtocol.AUTHORIZATION_HEADER_DELIMITER).replaceAll("\u3000 ", ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    while (replaceAll.contains("  ")) {
                        replaceAll = replaceAll.replace("  ", ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                    }
                    return replaceAll;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return str;
            }
        }
        return "";
    }

    public static boolean checkCategoryForShowNoti(int i, String str) throws Exception {
        if (str == null && str.length() <= 0) {
            return false;
        }
        if (i == 0) {
            if (str.startsWith("007")) {
                return true;
            }
        } else if (str.startsWith("001") || str.startsWith("003") || str.startsWith("004") || str.startsWith("007") || str.startsWith("013")) {
            return true;
        }
        return false;
    }
}