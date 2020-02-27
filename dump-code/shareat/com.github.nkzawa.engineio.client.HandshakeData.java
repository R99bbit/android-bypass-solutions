package com.github.nkzawa.engineio.client;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class HandshakeData {
    public long pingInterval;
    public long pingTimeout;
    public String sid;
    public String[] upgrades;

    HandshakeData(String data) throws JSONException {
        this(new JSONObject(data));
    }

    HandshakeData(JSONObject data) throws JSONException {
        JSONArray upgrades2 = data.getJSONArray("upgrades");
        int length = upgrades2.length();
        String[] _upgrades = new String[length];
        for (int i = 0; i < length; i++) {
            _upgrades[i] = upgrades2.getString(i);
        }
        this.sid = data.getString("sid");
        this.upgrades = _upgrades;
        this.pingInterval = data.getLong("pingInterval");
        this.pingTimeout = data.getLong("pingTimeout");
    }
}