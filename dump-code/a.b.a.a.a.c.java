package a.b.a.a.a;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.RingtoneManager;
import android.os.AsyncTask;
import android.os.PowerManager;
import androidx.core.app.NotificationCompat.BigPictureStyle;
import androidx.core.app.NotificationCompat.Builder;
import com.loplat.placeengine.ads.LoplatAdsActivity;
import com.loplat.placeengine.cloud.ResponseMessage.Advertisement;
import java.net.HttpURLConnection;
import java.net.URL;

/* compiled from: DisplayNotification */
public class c extends d {

    /* compiled from: DisplayNotification */
    private static class a extends AsyncTask<String, Void, Bitmap> {

        /* renamed from: a reason: collision with root package name */
        public Context f2a;
        public Builder b;
        public int c;
        public int d;
        public String e;
        public String f;
        public String g;

        public a(Context context, Advertisement advertisement) {
            this.f2a = context;
            this.c = advertisement.getMsg_id();
            this.d = advertisement.getCampaign_id();
            this.e = advertisement.getTitle();
            this.f = advertisement.getBody();
            this.g = advertisement.getImage_url();
            if (this.g != null) {
                Intent a2 = c.a(context, advertisement);
                b a3 = b.a(context);
                PendingIntent activity = PendingIntent.getActivity(context, advertisement.getCampaign_id(), a2, 134217728);
                this.b = new Builder(context, "plengi_ads").setPriority(1).setSound(RingtoneManager.getDefaultUri(2)).setAutoCancel(true).setSmallIcon(a.b.a.c.a.a(a3.c, (String) "lhtibaq5ot47p0xrinly", (String) "17", 17301576)).setLargeIcon(a3.a()).setContentTitle(this.e).setContentText(this.f);
                this.b.setContentIntent(activity);
                Intent intent = new Intent("com.loplat.ad.noti.delete");
                intent.setPackage(context.getPackageName());
                intent.putExtra("msg_id", this.c);
                this.b.setDeleteIntent(PendingIntent.getBroadcast(context, this.c, intent, 268435456));
            }
        }

        public Object doInBackground(Object[] objArr) {
            String[] strArr = (String[]) objArr;
            try {
                HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(this.g).openConnection();
                httpURLConnection.setDoInput(true);
                httpURLConnection.connect();
                return BitmapFactory.decodeStream(httpURLConnection.getInputStream());
            } catch (Exception unused) {
                return null;
            }
        }

        public void onPostExecute(Object obj) {
            Bitmap bitmap = (Bitmap) obj;
            super.onPostExecute(bitmap);
            if (bitmap != null) {
                BigPictureStyle bigPictureStyle = new BigPictureStyle(this.b);
                bigPictureStyle.bigPicture(bitmap).setBigContentTitle(this.e).setSummaryText(this.f);
                this.b.setStyle(bigPictureStyle);
                ((NotificationManager) this.f2a.getSystemService("notification")).notify(this.d, this.b.build());
                c.a(this.f2a);
            }
        }
    }

    public static Intent a(Context context, Advertisement advertisement) {
        Intent intent = new Intent(LoplatAdsActivity.NOTI_VIEW_AD_ACTION);
        intent.putExtra("msg_id", advertisement.getMsg_id());
        intent.putExtra("campaign_id", advertisement.getCampaign_id());
        intent.putExtra("title", advertisement.getTitle());
        intent.putExtra("target_intent", advertisement.getIntent());
        intent.putExtra("target_pkg", advertisement.getTarget_pkg());
        intent.setFlags(1342177280);
        intent.setClassName(context, LoplatAdsActivity.class.getName());
        return intent;
    }

    public static void a(Context context) {
        PowerManager powerManager = (PowerManager) context.getSystemService("power");
        if (!powerManager.isScreenOn()) {
            StringBuilder sb = new StringBuilder();
            sb.append(context.getPackageName());
            sb.append(":ads");
            powerManager.newWakeLock(268435462, sb.toString()).acquire(2000);
        }
    }
}