package com.nuvent.shareat.secure;

import android.content.Context;
import android.os.AsyncTask;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.event.SuccessCheckIntegrityEvent;
import de.greenrobot.event.EventBus;

public class CheckIntegrity extends AsyncTask<Void, Void, String> {
    private Context context;

    public CheckIntegrity(Context context2) {
        this.context = context2;
    }

    /* access modifiers changed from: protected */
    public void onPreExecute() {
        super.onPreExecute();
    }

    /* access modifiers changed from: protected */
    public String doInBackground(Void... params) {
        return AppEventsConstants.EVENT_PARAM_VALUE_NO;
    }

    /* access modifiers changed from: protected */
    public void onPostExecute(String result) {
        EventBus.getDefault().post(new SuccessCheckIntegrityEvent(result));
    }
}