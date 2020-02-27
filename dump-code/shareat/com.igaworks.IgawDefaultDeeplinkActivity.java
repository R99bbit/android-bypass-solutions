package com.igaworks;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.net.Uri;
import android.net.Uri.Builder;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

public class IgawDefaultDeeplinkActivity extends Activity {
    static boolean IntentForward = true;
    String IgawRedirectActivity = "com.unity3d.player.UnityPlayerActivity";

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        IgawCommon.registerReferrer(this);
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        IgawCommon.registerReferrer(this);
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        new Handler().postDelayed(new Runnable() {
            public void run() {
                IgawDefaultDeeplinkActivity.this.ParseIntent(IgawDefaultDeeplinkActivity.this);
            }
        }, 500);
    }

    /* access modifiers changed from: protected */
    public void onPause() {
        super.onPause();
    }

    /* access modifiers changed from: private */
    public void ParseIntent(Activity activity) {
        Uri iUri;
        try {
            ActivityInfo ai = getPackageManager().getActivityInfo(getComponentName(), 128);
            if (ai != null) {
                Bundle bundle = ai.metaData;
                if (bundle != null && bundle.containsKey("IgawRedirectActivity")) {
                    this.IgawRedirectActivity = String.valueOf(ai.metaData.get("IgawRedirectActivity"));
                }
                if (bundle != null && bundle.containsKey("IntentForward")) {
                    IntentForward = ai.metaData.getBoolean("IntentForward", true);
                }
            }
            Log.d(IgawConstant.QA_TAG, "RedirectActivity: " + this.IgawRedirectActivity + " . IntentForward: " + IntentForward);
            try {
                if (IntentForward) {
                    Intent i = activity.getIntent();
                    Uri iUri2 = i.getData();
                    if (iUri2 != null && iUri2.toString().contains("?")) {
                        try {
                            String uriStr = iUri2.toString();
                            try {
                                iUri = Uri.parse("http://igaworks.com" + uriStr.substring(uriStr.indexOf(63), uriStr.length()));
                            } catch (Exception e) {
                                iUri = Uri.parse("http://igaworks.com?dump=0");
                            }
                            Map<String, String> params = splitQuery(new URL(iUri.toString()));
                            if (uriStr != null && uriStr.length() > 0) {
                                i.setData(Uri.parse(makeNewDeeplinkWithoutCk(uriStr.substring(0, uriStr.indexOf(63)), params)));
                            }
                        } catch (Exception exception) {
                            exception.printStackTrace();
                        }
                    }
                    i.setClassName(this, this.IgawRedirectActivity);
                    activity.startActivity(i);
                    String dl = "null";
                    if (!(i == null || i.getData() == null)) {
                        dl = i.getData().toString();
                    }
                    IgawLogger.Logging(getApplicationContext(), IgawConstant.QA_TAG, "IgawDefaultDeeplinkActivity Deeplink: " + dl, 2, true);
                    finish();
                }
                Intent i2 = new Intent();
                i2.setClassName(this, this.IgawRedirectActivity);
                activity.startActivity(i2);
                finish();
            } catch (Exception e2) {
                IgawLogger.Logging(getApplicationContext(), IgawConstant.QA_TAG, "Can not redirect to " + this.IgawRedirectActivity + ". Launch default activity", 0, true);
                Intent i3 = activity.getPackageManager().getLaunchIntentForPackage(activity.getPackageName());
                i3.setFlags(603979776);
                activity.startActivity(i3);
            }
        } catch (Exception e3) {
            Log.e(IgawConstant.QA_TAG, "IgawDefaultDeeplinkActivity Error: " + e3.getMessage().toString());
        }
    }

    private Map<String, String> splitQuery(URL url) throws UnsupportedEncodingException {
        String[] pairs;
        Map<String, String> query_pairs = new LinkedHashMap<>();
        for (String pair : url.getQuery().split("&")) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    private String makeNewDeeplinkWithoutCk(String deeplink_uri, Map<String, String> parameters) {
        Builder b = Uri.parse(deeplink_uri).buildUpon();
        for (Entry<String, String> entry : parameters.entrySet()) {
            String key = entry.getKey();
            if (key != null && !key.equals("ck") && !key.equals("referrer") && !key.equals("isFacebookCpi") && !key.equals("igaw_eng") && !key.equals("igaw_deeplink_cvr") && !key.equals("sn") && !key.equals("cid")) {
                b.appendQueryParameter(entry.getKey(), entry.getValue());
            }
        }
        return b.build().toString();
    }
}