package com.nuvent.shareat.api.interest;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.store.ProfileStoreModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.util.ArrayList;
import java.util.Iterator;
import org.apache.http.Header;

public class InterestApi extends Request {
    public InterestApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        JsonArray array = new JsonParser().parse(responseText).getAsJsonObject().getAsJsonArray("store_list");
        ArrayList<ProfileStoreModel> models = new ArrayList<>();
        Iterator<JsonElement> it = array.iterator();
        while (it.hasNext()) {
            models.add((ProfileStoreModel) new Gson().fromJson(it.next(), ProfileStoreModel.class));
        }
        return models;
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}