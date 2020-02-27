package com.igaworks.commerce.model;

import android.util.Pair;
import com.google.firebase.analytics.FirebaseAnalytics.Param;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONObject;

public class CustomEventModel {
    private String eventName;
    private long mtime;
    private List<Pair<String, Object>> params;

    public CustomEventModel(String eventName2, List<Pair<String, Object>> params2, long mtime2) {
        this.eventName = eventName2;
        this.params = params2;
        this.mtime = mtime2;
    }

    public CustomEventModel(String json) {
        try {
            JSONObject item = new JSONObject(json);
            if (item.has("name")) {
                this.eventName = item.getString("name");
            }
            if (item.has(Param.VALUE)) {
                List<Pair<String, Object>> vals = new ArrayList<>();
                JSONObject obj = item.getJSONObject(Param.VALUE);
                if (obj != null) {
                    Iterator<String> keys = obj.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        vals.add(new Pair(key, obj.get(key)));
                    }
                    this.params = vals;
                }
            }
            if (item.has("mtime")) {
                this.mtime = item.getLong("mtime");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public CustomEventModel() {
    }

    public String getEventName() {
        return this.eventName;
    }

    public void setEventName(String eventName2) {
        this.eventName = eventName2;
    }

    public List<Pair<String, Object>> getParams() {
        return this.params;
    }

    public void setParams(List<Pair<String, Object>> params2) {
        this.params = params2;
    }

    public long getMtime() {
        return this.mtime;
    }

    public void setMtime(long mtime2) {
        this.mtime = mtime2;
    }

    public String toString() {
        return toJson().toString();
    }

    public JSONObject toJson() {
        JSONObject root = new JSONObject();
        try {
            root.put("name", this.eventName);
            JSONObject params2 = new JSONObject();
            if (this.params != null) {
                for (Pair<String, Object> nvp : this.params) {
                    params2.put((String) nvp.first, nvp.second);
                }
            }
            root.put(Param.VALUE, params2);
            root.put("mtime", this.mtime);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return root;
    }
}