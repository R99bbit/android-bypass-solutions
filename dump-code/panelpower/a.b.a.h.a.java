package a.b.a.h;

import android.os.Environment;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/* compiled from: FileLog */
public class a {

    /* renamed from: a reason: collision with root package name */
    public static String f43a;
    public static String b = null;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append(Environment.getExternalStorageDirectory().getAbsolutePath());
        sb.append("/log/");
        sb.append("com.loplat.placeengine");
        sb.append("/");
        f43a = sb.toString();
    }

    public static void a() {
        File file = new File(f43a);
        if (file.exists() && file.listFiles() != null && file.listFiles().length != 0) {
            for (File delete : file.listFiles()) {
                delete.delete();
            }
            file.delete();
        }
    }

    public static String b() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("MM-dd", Locale.KOREA);
        Date date = new Date();
        StringBuilder a2 = a.a.a.a.a.a("log_");
        a2.append(simpleDateFormat.format(date));
        a2.append(".txt");
        return a2.toString();
    }
}