package com.nuvent.shareat.api.intro;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.SignedModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;

public class SigninApi extends Request {
    public SigninApi(Context context) {
        super(context);
        this.serviceUrl = ApiUrl.EMAIL_CERTIFICATION_NORMAL;
        this.method = HttpRequest.METHOD_POST;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        SignedModel model = (SignedModel) new Gson().fromJson((JsonElement) new JsonParser().parse(responseText).getAsJsonObject(), SignedModel.class);
        String session = "";
        for (Header header : headers) {
            if (header.getName().equals(Names.SET_COOKIE)) {
                session = header.getValue().toString().split(";")[0];
            }
        }
        if (session != null && !session.isEmpty()) {
            SessionManager.getInstance().setSessionCookie(session);
        }
        return model;
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}