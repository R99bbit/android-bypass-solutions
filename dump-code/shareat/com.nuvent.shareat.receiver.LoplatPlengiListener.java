package com.nuvent.shareat.receiver;

import android.content.Intent;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.loplat.placeengine.PlengiListener;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Person;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.ShareatLogger;

public class LoplatPlengiListener implements PlengiListener {
    private final float VALID_VALUE = 0.2f;

    public void listen(PlengiResponse response) {
        System.out.println("LoplatPlengiListener: " + response.type);
        if (response.result == 2) {
            ShareatLogger.writeLog("[ERROR] Loplat error : " + response.errorReason);
        } else if (response.place != null && response.place.name != null && AppSettingManager.getInstance().getAutoBranchSearchStatus()) {
            ShareatLogger.writeLog("[DEBUG] Receive loplat event type : " + response.type);
            ShareatLogger.writeLog("[DEBUG] Receive loplat place name : " + response.place.name);
            ShareatLogger.writeLog("[DEBUG] Receive loplat client_code : " + response.place.client_code);
            if (0.2f > response.place.accuracy) {
                return;
            }
            if (response.type == 1) {
                String name = response.place.name;
                String str = response.place.tags;
                double d = response.place.lat;
                double d2 = response.place.lng;
                int floor = response.place.floor;
                String client_code = response.place.client_code;
                float accuracy = response.place.accuracy;
                float threshold = response.place.threshold;
                int i = response.placeEvent;
                if (name != null && !name.isEmpty() && true != name.contains("unknown")) {
                    String placeinfo = name + " \ub9e4\uc7a5 " + floor + "F";
                    if (accuracy > threshold) {
                    }
                    if (client_code != null) {
                        GAEvent.onUserTimings("\ub9e4\uc7a5\uc790\ub3d9\uc778\uc2dd\uc2dc\uac04", System.currentTimeMillis() - ShareatApp.getInstance().getStartSearchTime(), "\ub9e4\uc7a5\uc790\ub3d9\uc778\uc2dd\uc2dc\uac04", "\uc0ac\uc6a9\uc790\uc218\ub3d9\ud074\ub9ad");
                    }
                    sendLoplatResponseToApplication(placeinfo + " \ubc29\ubb38\ud558\uc168\ub098\uc694?", response);
                }
            } else if (response.type == 2) {
                int event = response.placeEvent;
                double d3 = response.place.lat;
                double d4 = response.place.lng;
                String str2 = response.place.name;
                if (event != 1 ? event != 2 : response.enterType != 0 && response.enterType == 1) {
                }
                sendLoplatResponseToApplication("", response);
            } else if (response.type == 5) {
                String colocateInfo = "";
                for (Person person : response.persons) {
                    colocateInfo = colocateInfo + person.uniqueUserId + " ";
                }
            }
        }
    }

    private void sendLoplatResponseToApplication(String response, PlengiResponse data) {
        Intent i = new Intent();
        i.setAction("com.nuvent.shareat.response");
        i.putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, data.type);
        i.putExtra("response", response);
        i.putExtra("clientCode", data.place.client_code);
        i.putExtra("event", data.placeEvent);
        i.putExtra("userX", data.place.lat);
        i.putExtra("userY", data.place.lng);
        i.putExtra("tags", data.place.tags);
        i.putExtra("categoryName", data.place.category);
        i.putExtra("partnerName", data.place.name);
        i.putExtra("enterType", data.enterType);
        i.putExtra("accuracy", data.place.accuracy);
        ShareatApp.getContext().sendBroadcast(i);
    }
}