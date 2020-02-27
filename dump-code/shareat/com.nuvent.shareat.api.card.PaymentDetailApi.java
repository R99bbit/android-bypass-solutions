package com.nuvent.shareat.api.card;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.payment.PaymentDetailModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class PaymentDetailApi extends Request {
    public PaymentDetailApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (PaymentDetailModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), PaymentDetailModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}