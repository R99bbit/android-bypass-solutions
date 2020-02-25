package com.embrain.panelpower.utils;

import android.content.Context;
import android.os.AsyncTask;
import com.embrain.panelbigdata.utils.StringUtils;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import java.io.IOException;

public class GoogleADIDUtils {

    private static class GoogleADIDTask extends AsyncTask<Void, Void, String> {
        private Context mContext;

        private GoogleADIDTask(Context context) {
            this.mContext = context;
        }

        /* access modifiers changed from: protected */
        public String doInBackground(Void... voidArr) {
            try {
                Info advertisingIdInfo = AdvertisingIdClient.getAdvertisingIdInfo(this.mContext);
                if (advertisingIdInfo != null) {
                    return advertisingIdInfo.getId();
                }
                return "";
            } catch (IOException e) {
                e.printStackTrace();
                return "";
            } catch (GooglePlayServicesRepairableException e2) {
                e2.printStackTrace();
                return "";
            } catch (GooglePlayServicesNotAvailableException e3) {
                e3.printStackTrace();
                return "";
            }
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(String str) {
            super.onPostExecute(str);
            if (!StringUtils.isEmpty(str)) {
                PanelPreferenceUtils.setAdId(this.mContext, str);
            }
        }
    }

    public static String getGoogleADID(Context context) {
        String adId = PanelPreferenceUtils.getAdId(context);
        if (StringUtils.isEmpty(adId)) {
            new GoogleADIDTask(context).execute(new Void[0]);
        }
        return adId;
    }
}