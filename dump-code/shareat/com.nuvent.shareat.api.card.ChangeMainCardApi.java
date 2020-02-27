package com.nuvent.shareat.api.card;

import android.content.Context;
import com.nuvent.shareat.api.Request;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class ChangeMainCardApi extends Request {
    public ChangeMainCardApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_PUT;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return responseText;
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}