package com.nuvent.shareat.api.member;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.event.RequestProfileUpdateEvent;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.user.UserResultModel;
import de.greenrobot.event.EventBus;
import io.fabric.sdk.android.services.network.HttpRequest;
import org.apache.http.Header;

public class UserInfoApi extends Request {
    public static final int REQUEST_TYPE_EDIT_USER_INFO = 2;
    public static final int REQUEST_TYPE_GET_USER_INFO = 1;

    public UserInfoApi(Context context, int type) {
        super(context);
        this.serviceUrl = ApiUrl.USER_INFO;
        this.method = 1 == type ? HttpRequest.METHOD_GET : HttpRequest.METHOD_POST;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        JsonObject object = new JsonParser().parse(responseText).getAsJsonObject();
        if (this.method.equals(HttpRequest.METHOD_GET)) {
            SessionManager.getInstance().setUserJsonString(responseText);
            return (UserResultModel) new Gson().fromJson((JsonElement) object, UserResultModel.class);
        }
        BaseResultModel model = (BaseResultModel) new Gson().fromJson((JsonElement) object, BaseResultModel.class);
        if (!model.getResult().equals("Y")) {
            return model;
        }
        EventBus.getDefault().post(new RequestProfileUpdateEvent());
        return model;
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}