package a.b.a.h;

import android.util.Log;
import com.loplat.placeengine.utils.LoplatLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* compiled from: JsonLog */
public class b {

    /* renamed from: a reason: collision with root package name */
    public static String f44a = "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550";
    public static String b = "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550";

    public static void a(String str, String str2) {
        try {
            if (str2.startsWith("{")) {
                str2 = new JSONObject(str2).toString(4);
            } else if (str2.startsWith("[")) {
                str2 = new JSONArray(str2).toString(4);
            }
        } catch (JSONException unused) {
        }
        Log.d(str, f44a);
        for (String append : str2.split(LoplatLogger.LINE_SEPARATOR)) {
            StringBuilder sb = new StringBuilder();
            sb.append("\u2551 ");
            sb.append(append);
            Log.d(str, sb.toString());
        }
        Log.d(str, b);
    }

    public static String a(String str) {
        StringBuilder sb = new StringBuilder();
        try {
            if (str.startsWith("{")) {
                str = new JSONObject(str).toString(4);
            } else if (str.startsWith("[")) {
                str = new JSONArray(str).toString(4);
            }
        } catch (JSONException unused) {
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(f44a);
        sb2.append("\n");
        sb.append(sb2.toString());
        for (String append : str.split(LoplatLogger.LINE_SEPARATOR)) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("\u2551 ");
            sb3.append(append);
            sb3.append("\n");
            sb.append(sb3.toString());
        }
        sb.append(b);
        return sb.toString();
    }
}