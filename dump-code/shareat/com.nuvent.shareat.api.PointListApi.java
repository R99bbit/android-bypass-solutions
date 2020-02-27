package com.nuvent.shareat.api;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.model.PointModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class PointListApi extends Request {
    public PointListApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.POINT_LIST;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (PointModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), PointModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}