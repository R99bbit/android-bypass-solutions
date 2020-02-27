package com.igaworks.dao;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import java.util.Map.Entry;
import org.json.JSONException;
import org.json.JSONObject;

public class LocalDemograhpicDAO {
    private static final String LocalDemograhpicDAO_NAME = "LocalDemograhpicDAO";
    private static LocalDemograhpicDAO singleton;
    private SharedPreferences LocalDemograhpicSP;
    private Editor editor = this.LocalDemograhpicSP.edit();

    private LocalDemograhpicDAO(Context context) {
        this.LocalDemograhpicSP = context.getSharedPreferences(LocalDemograhpicDAO_NAME, 0);
    }

    public static LocalDemograhpicDAO getInstance(Context context) {
        if (singleton == null) {
            synchronized (LocalDemograhpicDAO.class) {
                try {
                    if (singleton == null) {
                        singleton = new LocalDemograhpicDAO(context);
                    }
                }
            }
        }
        return singleton;
    }

    public void save_demographic_local(String key, String value) {
        if (value != null) {
            try {
                if (!value.equals("")) {
                    this.editor.putString(key, value);
                    this.editor.apply();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public JSONObject convertDemographicInfoFromSP2JSONObject(Context context) {
        JSONObject json = new JSONObject();
        try {
            for (Entry<String, ?> entry : context.getSharedPreferences(LocalDemograhpicDAO_NAME, 0).getAll().entrySet()) {
                json.put(entry.getKey(), (String) entry.getValue());
            }
            return json;
        } catch (JSONException e) {
            e.printStackTrace();
            return new JSONObject();
        }
    }
}