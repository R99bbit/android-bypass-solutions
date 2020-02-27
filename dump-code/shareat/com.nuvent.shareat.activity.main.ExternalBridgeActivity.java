package com.nuvent.shareat.activity.main;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import com.igaworks.IgawCommon;
import com.igaworks.interfaces.DeferredLinkListener;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.intro.SplashActivity;
import com.nuvent.shareat.model.PushModel;
import org.json.JSONObject;

public class ExternalBridgeActivity extends BaseActivity {
    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        postExternalData(intent);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        IgawCommon.registerReferrer(this);
        postExternalData(getIntent());
        IgawCommon.setDeferredLinkListener(this, new DeferredLinkListener() {
            public void onReceiveDeeplink(String s) {
                try {
                    Log.i("IGAWORKS", "Facebook Deeplink: " + s);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void postExternalData(Intent data) {
        Intent intent = new Intent(this, SplashActivity.class);
        if (data.getData() == null || !data.getDataString().contains("shareat://shareat.me/")) {
            if (data.getData() != null && data.getDataString().contains("share://shareat.me/")) {
                PushModel model = new PushModel();
                model.setType(99);
                model.setPartner_sno(data.getData().getQueryParameter("psno"));
                intent.putExtra("push", model);
            } else if (data.getData() == null || data.getData().getQuery() == null) {
                intent.putExtra("push", data.getSerializableExtra("push"));
            } else {
                try {
                    String partnerSno = new JSONObject(data.getData().getQueryParameter("store")).getString("partnerSno");
                    PushModel model2 = new PushModel();
                    model2.setType(99);
                    model2.setPartner_sno(partnerSno);
                    intent.putExtra("push", model2);
                } catch (Exception e) {
                    e.printStackTrace();
                    finish();
                    return;
                }
            }
        } else if (!data.getDataString().equals("shareat://shareat.me/") && !data.getDataString().equals("shareat://shareat.me/mainlist")) {
            PushModel model3 = new PushModel();
            model3.setCustomScheme(data.getDataString());
            intent.putExtra("push", model3);
        }
        intent.setFlags(603979776);
        startActivity(intent);
        overridePendingTransition(0, 0);
        finish(false);
    }
}