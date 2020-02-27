package com.nuvent.shareat.api.intro;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.VersionModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class VersionCheckApi extends Request {
    public VersionCheckApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.VERSION_CHECK;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (VersionModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), VersionModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}