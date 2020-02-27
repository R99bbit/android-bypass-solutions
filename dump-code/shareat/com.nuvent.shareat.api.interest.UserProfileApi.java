package com.nuvent.shareat.api.interest;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.user.UserProfileModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class UserProfileApi extends Request {
    public UserProfileApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        return (UserProfileModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject().getAsJsonObject("user_info"), UserProfileModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}