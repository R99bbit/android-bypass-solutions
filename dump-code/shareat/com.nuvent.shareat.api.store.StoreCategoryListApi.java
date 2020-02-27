package com.nuvent.shareat.api.store;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.store.CategoryResultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class StoreCategoryListApi extends Request {
    public StoreCategoryListApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.STORE_CATEGORY_LIST;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (CategoryResultModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), CategoryResultModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}