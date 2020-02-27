package com.nuvent.shareat.api;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.model.CouponModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class CouponListApi extends Request {
    public CouponListApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.COUPON_LIST;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (CouponModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), CouponModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}