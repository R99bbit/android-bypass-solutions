package com.nuvent.shareat.manager.app;

import android.content.SharedPreferences.Editor;
import android.support.graphics.drawable.PathInterpolatorCompat;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.model.store.LocationModel;
import java.util.ArrayList;

public class ParamManager {
    private static final String KEY_CATEGORY = "KEY_CATEGORY";
    private static final String KEY_CATEGORY_SORT_TYPE = "KEY_CATEGORY_SORT_TYPE";
    private static final String KEY_LOCATION_JSON = "KEY_LOCATION_JSON";
    private static final String KEY_RECENT_LOCATION_JSON = "KEY_RECENT_LOCATION_JSON";
    private static final String KEY_STORE_LIMIT_DISTANCE = "KEY_STORE_LIMIT_DISTANCE";
    public static ParamManager mInstance = new ParamManager();

    public static synchronized ParamManager getInstance() {
        ParamManager paramManager;
        synchronized (ParamManager.class) {
            try {
                paramManager = mInstance;
            }
        }
        return paramManager;
    }

    public int getSortType() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getInt(KEY_CATEGORY_SORT_TYPE, 1);
    }

    public void setSortType(int value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putInt(KEY_CATEGORY_SORT_TYPE, value);
        editor.commit();
    }

    public int getLimitDistance() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getInt(KEY_STORE_LIMIT_DISTANCE, PathInterpolatorCompat.MAX_NUM_POINTS);
    }

    public void setLimitDistance(int value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putInt(KEY_STORE_LIMIT_DISTANCE, value);
        editor.commit();
    }

    public String getCategory() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_CATEGORY, "");
    }

    public void setCategory(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_CATEGORY, value);
        editor.commit();
    }

    public String getLocationJsonString() {
        return ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_LOCATION_JSON, "");
    }

    public void setLocationJsonString(String value) {
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_LOCATION_JSON, value);
        editor.commit();
    }

    public void setRecentSetModel(LocationModel model) {
        String toJson = new GsonBuilder().create().toJson((Object) model);
        Editor editor = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).edit();
        editor.putString(KEY_RECENT_LOCATION_JSON, toJson);
        editor.commit();
    }

    public LocationModel getRecentSetModel() {
        String fromJson = ShareatApp.getInstance().getSharedPreferences("com.nuvent.shareat", 0).getString(KEY_RECENT_LOCATION_JSON, "");
        if (fromJson.isEmpty()) {
            return new LocationModel();
        }
        return (LocationModel) new Gson().fromJson((JsonElement) new JsonParser().parse(fromJson).getAsJsonObject(), LocationModel.class);
    }

    public void addModel(LocationModel model) {
        ArrayList<LocationModel> models;
        setRecentSetModel(model);
        if (getLocationJsonString().isEmpty()) {
            models = new ArrayList<>();
        } else {
            models = (ArrayList) new Gson().fromJson((JsonElement) new JsonParser().parse(getLocationJsonString()).getAsJsonArray(), new TypeToken<ArrayList<LocationModel>>() {
            }.getType());
        }
        if (2 == models.size()) {
            ArrayList<LocationModel> tempModels = new ArrayList<>();
            tempModels.add(0, models.get(0));
            tempModels.add(0, model);
            models = tempModels;
        } else {
            models.add(0, model);
        }
        setLocationJsonString(new GsonBuilder().create().toJson((Object) models));
    }

    public void updateModel(LocationModel model) {
        ArrayList<LocationModel> models;
        if (getLocationJsonString().isEmpty()) {
            models = new ArrayList<>();
        } else {
            models = (ArrayList) new Gson().fromJson((JsonElement) new JsonParser().parse(getLocationJsonString()).getAsJsonArray(), new TypeToken<ArrayList<LocationModel>>() {
            }.getType());
        }
        for (int i = 0; i < models.size(); i++) {
            if (true == models.get(i).getAreaId().equals(model.getAreaId())) {
                models.set(i, model);
            }
        }
        setLocationJsonString(new GsonBuilder().create().toJson((Object) models));
    }

    public ArrayList<LocationModel> getModels() {
        if (getLocationJsonString().isEmpty()) {
            return new ArrayList<>();
        }
        return (ArrayList) new Gson().fromJson((JsonElement) new JsonParser().parse(getLocationJsonString()).getAsJsonArray(), new TypeToken<ArrayList<LocationModel>>() {
        }.getType());
    }
}