package com.nuvent.shareat.util;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class StoryLink {
    private static String storyLinkApiVersion = "1.0";
    private static Charset storyLinkCharset = Charset.forName("UTF-8");
    private static String storyLinkEncoding = storyLinkCharset.name();
    private static String storyLinkURLBaseString = "storylink://posting";
    private static StoryLink stroyLink = null;
    private Context context;
    private String params = getBaseStoryLinkUrl();

    private StoryLink(Context context2) {
        this.context = context2;
    }

    public static StoryLink getLink(Context context2) {
        if (stroyLink != null) {
            return stroyLink;
        }
        return new StoryLink(context2);
    }

    private void openStoryLink(Activity activity, String params2) {
        activity.startActivity(new Intent("android.intent.action.SEND", Uri.parse(params2)));
    }

    public String openKakaoLink(Activity activity, String post, String appId, String appVer, String appName, String encoding, Map<String, Object> urlInfoAndroid) {
        if (isEmptyString(post) || isEmptyString(appId) || isEmptyString(appVer) || isEmptyString(appName) || isEmptyString(encoding)) {
            throw new IllegalArgumentException();
        }
        try {
            if (storyLinkCharset.equals(Charset.forName(encoding))) {
                post = new String(post.getBytes(encoding), storyLinkEncoding);
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        this.params = getBaseStoryLinkUrl();
        appendParam("post", post);
        appendParam("appid", appId);
        appendParam(KakaoTalkLinkProtocol.APP_VER, appVer);
        appendParam(KakaoTalkLinkProtocol.API_VER, storyLinkApiVersion);
        appendParam("appname", appName);
        appendUrlInfo(urlInfoAndroid);
        return this.params;
    }

    public boolean isAvailableIntent() {
        List<ResolveInfo> queryIntentActivities = this.context.getPackageManager().queryIntentActivities(new Intent("android.intent.action.SEND", Uri.parse(storyLinkURLBaseString)), 65536);
        if (queryIntentActivities != null && queryIntentActivities.size() > 0) {
            return true;
        }
        return false;
    }

    private boolean isEmptyString(String str) {
        return str == null || str.trim().length() == 0;
    }

    private void appendParam(String name, String value) {
        try {
            this.params += name + "=" + URLEncoder.encode(value, storyLinkEncoding) + "&";
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private void appendUrlInfo(Map<String, Object> urlInfoAndroid) {
        this.params += "urlinfo=";
        JSONObject metaObj = new JSONObject();
        try {
            for (String key : urlInfoAndroid.keySet()) {
                if ("imageurl".equals(key)) {
                    metaObj.put(key, getImageUrl(urlInfoAndroid.get(key)));
                } else {
                    metaObj.put(key, urlInfoAndroid.get(key));
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        try {
            this.params += URLEncoder.encode(metaObj.toString(), storyLinkEncoding);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
    }

    private JSONArray getImageUrl(Object imageUrl) {
        JSONArray arrImageUrl = new JSONArray();
        String[] objImageUrl = (String[]) imageUrl;
        for (String put : objImageUrl) {
            arrImageUrl.put(put);
        }
        return arrImageUrl;
    }

    private String getBaseStoryLinkUrl() {
        return storyLinkURLBaseString + "?";
    }

    public void openStoryLinkImageApp(Activity activity, String path) {
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setType("image/png");
        intent.putExtra("android.intent.extra.STREAM", Uri.parse(path));
        intent.setPackage(ExternalApp.KAKAOSTORY);
        activity.startActivity(intent);
    }
}