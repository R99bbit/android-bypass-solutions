package com.nuvent.shareat.api.card;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.user.CardResultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class MyCardListApi extends Request {
    public MyCardListApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        JsonObject object = new JsonParser().parse(responseText).getAsJsonObject();
        SessionManager.getInstance().setCardListJsonString(responseText);
        return (CardResultModel) new Gson().fromJson((JsonElement) object, CardResultModel.class);
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}