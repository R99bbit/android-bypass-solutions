package com.nuvent.shareat.api.search;

import android.content.Context;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class SearchApi extends Request {
    public static final int ITEM_LIMIT_COUNT = 20;

    public SearchApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.SEARCH_URL;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return new JsonParser().parse(responseText).getAsJsonObject();
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}