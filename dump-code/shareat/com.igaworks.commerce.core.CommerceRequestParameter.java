package com.igaworks.commerce.core;

import android.content.Context;
import com.igaworks.commerce.model.CommerceV2EventItem;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CommerceRequestParameter {
    private static RequestParameter parameter;

    public static String getCommerceEventParameter(Context context, String adid, boolean adidOptOut, List<String> items, int ServerType) {
        if (parameter == null) {
            parameter = RequestParameter.getATRequestParameter(context);
        }
        try {
            JSONObject base = new JSONObject(parameter.getTrackingParameterForADBrix(context, null, null, null, adid, adidOptOut));
            JSONArray arr = new JSONArray();
            for (String item : items) {
                try {
                    arr.put(new JSONObject(item));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (ServerType == 1) {
                base.put("commerce_events", arr);
            } else {
                base.put("commerce_event_info", arr);
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "CommerceParameter > commerce event Parameter : " + base.toString(), 3);
            return base.toString();
        } catch (JSONException e2) {
            e2.printStackTrace();
            return "{}";
        }
    }

    public static String getCommerceV2EventParameter(Context context, String adid, boolean adidOptOut, List<CommerceV2EventItem> items, int ServerType) {
        if (parameter == null) {
            parameter = RequestParameter.getATRequestParameter(context);
        }
        try {
            JSONObject base = new JSONObject(parameter.getTrackingParameterForADBrix(context, null, null, null, adid, adidOptOut));
            JSONArray arr = new JSONArray();
            for (CommerceV2EventItem item : items) {
                try {
                    arr.put(new JSONObject(item.getJson()));
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
            if (ServerType == 1) {
                base.put("commerce_events", arr);
            } else {
                base.put("commerce_event_info", arr);
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "getCommerceV2EventParameter > commerceV2 event Parameter : " + base.toString(), 3);
            return base.toString();
        } catch (JSONException e2) {
            e2.printStackTrace();
            return "{}";
        }
    }
}