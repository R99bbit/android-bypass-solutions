package com.nuvent.shareat.api.common;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.RecommendLookAroundModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class RecommendLookAroundApi extends Request {
    public RecommendLookAroundApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.MAIN_LIST_EMPTY_RECOMMEND_LOOK_AROUND_URL;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (RecommendLookAroundModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), RecommendLookAroundModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}