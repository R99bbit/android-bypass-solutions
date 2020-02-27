package com.nuvent.shareat.api;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.model.delivery.DeliveryPossibleAreaModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class DeliveryPossibleAreaApi extends Request {
    public DeliveryPossibleAreaApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.DELIVERY_POSSIBLE_REGION_URL;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (DeliveryPossibleAreaModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), DeliveryPossibleAreaModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}