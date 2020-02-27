package com.nuvent.shareat.api;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressResultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class DeliveryShippingAddressApi extends Request {
    public DeliveryShippingAddressApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.DELIVERY_SHIPPING_ADDRESS_URL;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (DeliveryShippingAddressResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), DeliveryShippingAddressResultModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}