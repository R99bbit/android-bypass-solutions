package com.nuvent.shareat.api;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.model.CouponDetailModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class CouponGroupInfoApi extends Request {
    public CouponGroupInfoApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.GROUP_COUPON_INFO;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (CouponDetailModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), CouponDetailModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}