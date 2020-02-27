package com.nuvent.shareat.api.common;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.MapDataModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class MapDataApi extends Request {
    public MapDataApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.MAP_DATA;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (MapDataModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), MapDataModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}