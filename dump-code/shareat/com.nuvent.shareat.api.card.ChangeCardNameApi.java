package com.nuvent.shareat.api.card;

import android.content.Context;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class ChangeCardNameApi extends Request {
    public ChangeCardNameApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.PAYMENT_NAME_CHANGE;
        this.method = HttpRequest.METHOD_POST;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return responseText;
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}