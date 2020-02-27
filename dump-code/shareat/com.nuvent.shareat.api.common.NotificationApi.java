package com.nuvent.shareat.api.common;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.NotificationResultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class NotificationApi extends Request {
    public static final int REQUEST_TYPE_GET = 1;
    public static final int REQUEST_TYPE_POST = 2;

    public NotificationApi(Context context, int type, boolean isMember) {
        super(context);
        this.serviceUrl = isMember ? ApiUrl.NOTIFICATION_URL : ApiUrl.NON_USER_NOTIFICATION_URL;
        this.method = type == 1 ? HttpRequest.METHOD_GET : HttpRequest.METHOD_POST;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        JsonObject object = new JsonParser().parse(responseText).getAsJsonObject();
        if (this.method.equals(HttpRequest.METHOD_GET)) {
            return (NotificationResultModel) new Gson().fromJson((JsonElement) object, NotificationResultModel.class);
        }
        return (BaseResultModel) new Gson().fromJson((JsonElement) object, BaseResultModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}