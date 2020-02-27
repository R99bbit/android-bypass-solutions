package com.nuvent.shareat.api;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.model.delivery.DeliveryPaymentCancelResultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class DeliveryPaymentCancelApi extends Request {
    public DeliveryPaymentCancelApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.DELIVERY_PAYMENT_CANCEL_URL;
        this.method = HttpRequest.METHOD_POST;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (DeliveryPaymentCancelResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), DeliveryPaymentCancelResultModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}