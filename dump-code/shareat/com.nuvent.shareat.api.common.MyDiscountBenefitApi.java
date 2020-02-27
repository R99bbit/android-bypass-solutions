package com.nuvent.shareat.api.common;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.MyDiscountBenefitModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class MyDiscountBenefitApi extends Request {
    public MyDiscountBenefitApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.MY_DISCOUNT_BENEFIT_URL;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (MyDiscountBenefitModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), MyDiscountBenefitModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}