package com.igaworks.adbrix.json;

import com.igaworks.adbrix.model.ViralInfoModel;
import com.igaworks.adbrix.model.ViralUrlModel;
import com.igaworks.net.HttpManager;
import org.json.JSONObject;

public class JSON2ViralConverter {
    public static ViralInfoModel convert2ViralInfo(String src) {
        try {
            ViralInfoModel result = new ViralInfoModel();
            try {
                JSONObject root = new JSONObject(src);
                if (root.has("IsTest")) {
                    result.setTest(root.getBoolean("IsTest"));
                }
                if (root.has(HttpManager.RESULT)) {
                    result.setResult(root.getBoolean(HttpManager.RESULT));
                }
                if (root.has("ResultCode")) {
                    result.setResultCode(root.getInt("ResultCode"));
                }
                if (root.has("ResultMsg")) {
                    result.setResultMsg(root.getString("ResultMsg"));
                }
                if (root.has("ImageURL")) {
                    result.setImageURL(root.getString("ImageURL"));
                }
                if (root.has("ItemName")) {
                    result.setItemName(root.getString("ItemName"));
                }
                if (root.has("ItemQuantity")) {
                    result.setItemQuantity(root.getString("ItemQuantity"));
                }
                ViralInfoModel viralInfoModel = result;
                return result;
            } catch (Exception e) {
                e = e;
                ViralInfoModel viralInfoModel2 = result;
                e.printStackTrace();
                return null;
            }
        } catch (Exception e2) {
            e = e2;
            e.printStackTrace();
            return null;
        }
    }

    public static ViralUrlModel convert2ViralUrl(String src) {
        try {
            ViralUrlModel result = new ViralUrlModel();
            try {
                JSONObject root = new JSONObject(src);
                if (root.has("IsTest")) {
                    result.setTest(root.getBoolean("IsTest"));
                }
                if (root.has(HttpManager.RESULT)) {
                    result.setResult(root.getBoolean(HttpManager.RESULT));
                }
                if (root.has("ResultCode")) {
                    result.setResultCode(root.getInt("ResultCode"));
                }
                if (root.has("ResultMsg")) {
                    result.setResultMsg(root.getString("ResultMsg"));
                }
                if (root.has("TrackingURL")) {
                    result.setTrackingURL(root.getString("TrackingURL"));
                }
                ViralUrlModel viralUrlModel = result;
                return result;
            } catch (Exception e) {
                e = e;
                ViralUrlModel viralUrlModel2 = result;
                e.printStackTrace();
                return null;
            }
        } catch (Exception e2) {
            e = e2;
            e.printStackTrace();
            return null;
        }
    }
}