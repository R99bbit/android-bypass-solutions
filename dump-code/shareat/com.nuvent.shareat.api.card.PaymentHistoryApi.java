package com.nuvent.shareat.api.card;

import android.content.Context;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.Request;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class PaymentHistoryApi extends Request {
    public PaymentHistoryApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return new JsonParser().parse(responseText).getAsJsonObject().getAsJsonArray("result_list");
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}