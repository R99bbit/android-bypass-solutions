package com.nuvent.shareat.api.interest;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nuvent.shareat.api.Request;
import com.nuvent.shareat.model.store.ReviewModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.util.ArrayList;
import java.util.Iterator;
import org.apache.http.Header;

public class ReviewApi extends Request {
    public ReviewApi(Context context, String url) {
        super(context);
        this.serviceUrl = url;
        this.method = HttpRequest.METHOD_GET;
    }

    /* access modifiers changed from: protected */
    public Object parseContent(Header[] headers, String responseText) throws Exception {
        JsonArray array = new JsonParser().parse(responseText).getAsJsonObject().getAsJsonArray("result_list");
        ArrayList<ReviewModel> models = new ArrayList<>();
        Iterator<JsonElement> it = array.iterator();
        while (it.hasNext()) {
            models.add((ReviewModel) new Gson().fromJson(it.next(), ReviewModel.class));
        }
        return models;
    }

    /* access modifiers changed from: protected */
    public Object parseErrorCode(String responseText) throws Exception {
        return null;
    }
}