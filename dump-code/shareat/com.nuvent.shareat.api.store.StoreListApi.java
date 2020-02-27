package com.nuvent.shareat.api.store;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.store.StoreResultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class StoreListApi extends Request {
    public StoreListApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.STORE_STREAM_LIST;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        JsonObject asJsonObject = new JsonParser().parse(responseText).getAsJsonObject();
        return (StoreResultModel) new Gson().fromJson(responseText, StoreResultModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}