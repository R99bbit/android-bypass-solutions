package com.igaworks.adbrix.json;

import android.content.Context;
import com.igaworks.adbrix.db.ScheduleDAO;
import com.igaworks.adbrix.model.RealRewardResultModel;
import com.igaworks.adbrix.model.ScheduleContainer;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.gson.Gson;
import com.igaworks.model.ParticipationProgressModel;
import com.igaworks.model.ParticipationProgressResponseModel;
import com.igaworks.net.HttpManager;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

public class JSON2ScheduleConverter {
    public static ScheduleContainer json2ScheduleV2(final Context context, final String json) {
        ScheduleContainer result = null;
        if (json == null) {
            return null;
        }
        try {
            JSONObject root = new JSONObject(json);
            if (root.has("ResultCode")) {
                int resultCode = root.getInt("ResultCode");
                if (resultCode == 1001) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixTracer, schedule received : result code = 1001, load local schedule.", 3, true);
                    return ScheduleDAO.getInstance().getSchedule(context);
                } else if (resultCode != 1) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixTracer, schedule received : result code invalid. result code = " + resultCode, 3, true);
                    return null;
                }
            }
            if (!root.has(HttpManager.DATA)) {
                return null;
            }
            JSONObject data = root.getJSONObject(HttpManager.DATA);
            if (data != null) {
                new Thread(new Runnable() {
                    public void run() {
                        ScheduleDAO.getInstance().saveSchedule(context, json);
                    }
                }).start();
                result = (ScheduleContainer) new Gson().fromJson(data.toString(), ScheduleContainer.class);
                if (!data.has("Schedule")) {
                    return null;
                }
                data.getJSONObject("Schedule").has("Engagement");
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static ParticipationProgressResponseModel json2ParticipationProgressModel(String json) {
        ParticipationProgressResponseModel result = null;
        if (json == null) {
            return null;
        }
        try {
            JSONObject root = new JSONObject(json);
            ParticipationProgressResponseModel result2 = new ParticipationProgressResponseModel();
            try {
                if (root.has(HttpManager.RESULT)) {
                    result2.setResult(root.getBoolean(HttpManager.RESULT));
                }
                if (root.has("ResultCode")) {
                    result2.setResultCode(root.getInt("ResultCode"));
                }
                if (root.has("ResultMsg")) {
                    result2.setResultMessage(root.getString("ResultMsg"));
                }
                if (!root.has(HttpManager.DATA) || root.isNull(HttpManager.DATA)) {
                    ParticipationProgressResponseModel participationProgressResponseModel = result2;
                    return result2;
                }
                JSONArray data = root.getJSONArray(HttpManager.DATA);
                if (data != null) {
                    List<ParticipationProgressModel> ppm = new ArrayList<>();
                    for (int i = 0; i < data.length(); i++) {
                        JSONObject aConversion = data.getJSONObject(i);
                        if (aConversion.has("ConversionKey")) {
                            ppm.add(new ParticipationProgressModel(aConversion.getInt("ConversionKey")));
                        }
                    }
                    result2.setData(ppm);
                    result = result2;
                } else {
                    result = result2;
                }
                return result;
            } catch (Exception e) {
                e = e;
                result = result2;
                e.printStackTrace();
                return result;
            }
        } catch (Exception e2) {
            e = e2;
            e.printStackTrace();
            return result;
        }
    }

    public static RealRewardResultModel json2RealReward(String json) {
        RealRewardResultModel result = null;
        if (json == null) {
            return null;
        }
        try {
            JSONObject root = new JSONObject(json);
            RealRewardResultModel result2 = new RealRewardResultModel();
            try {
                if (root.has(HttpManager.RESULT)) {
                    result2.setResult(root.getBoolean(HttpManager.RESULT));
                }
                if (root.has("ResultCode")) {
                    result2.setResultCode(root.getInt("ResultCode"));
                }
                if (root.has("ResultMsg")) {
                    result2.setResultMessage(root.getString("ResultMsg"));
                }
                if (!root.has(HttpManager.DATA) || root.isNull(HttpManager.DATA)) {
                    RealRewardResultModel realRewardResultModel = result2;
                    return result2;
                }
                JSONObject data = root.getJSONObject(HttpManager.DATA);
                if (data != null) {
                    if (data.has("SessionNo") && !data.isNull("SessionNo")) {
                        result2.setSessionNo(data.getLong("SessionNo"));
                    }
                    if (data.has("SuccessMsg") && !data.isNull("SuccessMsg")) {
                        result2.setSuccessMsg(data.getString("SuccessMsg"));
                    }
                    if (data.has("FailMsg") && !data.isNull("FailMsg")) {
                        result2.setFailMsg(data.getString("FailMsg"));
                    }
                    if (data.has("RewardName") && !data.isNull("RewardName")) {
                        result2.setRewardName(data.getString("RewardName"));
                    }
                    if (data.has("RewardQuantity") && !data.isNull("RewardQuantity")) {
                        result2.setRewardQuantity(data.getInt("RewardQuantity"));
                    }
                    if (data.has("RewardImage") && !data.isNull("RewardImage")) {
                        result2.setRewardImage(data.getString("RewardImage"));
                    }
                    if (data.has("StatusCodes") && !data.isNull("StatusCodes")) {
                        result2.setStatusCodes(data.getInt("StatusCodes"));
                    }
                    if (data.has("Type") && !data.isNull("Type")) {
                        result2.setType(data.getString("Type"));
                        result = result2;
                        return result;
                    }
                }
                result = result2;
                return result;
            } catch (Exception e) {
                e = e;
                result = result2;
                e.printStackTrace();
                return result;
            }
        } catch (Exception e2) {
            e = e2;
            e.printStackTrace();
            return result;
        }
    }
}