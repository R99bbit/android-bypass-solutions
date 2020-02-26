package com.embrain.panelpower.utils;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.widget.Toast;
import androidx.annotation.NonNull;
import com.embrain.panelbigdata.utils.DeviceUtils;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.PanelApplication;
import com.embrain.panelpower.R;
import com.embrain.panelpower.UserInfoManager;
import com.embrain.panelpower.UserInfoManager.UserInfo;
import com.embrain.panelpower.views.SharePopup;
import com.embrain.panelpower.vo.ShareInfo;
import com.embrain.panelpower.vo.share.EventItemVO;
import com.embrain.panelpower.vo.share.SurveyOfflineItemObj;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.kakao.kakaolink.v2.KakaoLinkResponse;
import com.kakao.kakaolink.v2.KakaoLinkService;
import com.kakao.message.template.ButtonObject;
import com.kakao.message.template.ContentObject;
import com.kakao.message.template.FeedTemplate;
import com.kakao.message.template.LinkObject;
import com.kakao.message.template.LinkObject.Builder;
import com.kakao.message.template.LocationTemplate;
import com.kakao.message.template.TemplateParams;
import com.kakao.message.template.TextTemplate;
import com.kakao.network.ErrorResult;
import com.kakao.network.callback.ResponseCallback;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Map;

public class ShareUtils {
    private static final String BAND_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    private static final String BASE_FACEBOOK = "https://www.facebook.com/sharer.php?";
    private static final String BASE_KAKAO_STORY = "storylink://posting?";
    private static final String BASE_TWITTER = "http://twitter.com/intent/tweet?";
    private static final String DEFAULT_ENCODING = "UTF-8";
    private static final String DEFAULT_SHARE_BUTTON_TEXT = "\ubc14\ub85c\uac00\uae30";
    private static final String FACEBOOK_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    private static final String KAKAO_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    private static final String KAKAO_STORY_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    private static final String LINE_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    private static final String LINE_WEB_SURVEY_SNS_URL;
    private static final String PKG_BAND = "com.nhn.android.band";
    private static final String PKG_FACEBOOK = "com.facebook.katana";
    private static final String PKG_KAKAO = "com.kakao.talk";
    private static final String PKG_LINE = "jp.naver.line.android";
    private static final String PKG_STORY = "com.kakao.story";
    private static final String PKG_TWITTER = "com.twitter.android";
    private static final String SMS_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    private static String[] SNS_PKG_LIST_EVENT = {PKG_KAKAO, PKG_STORY, PKG_LINE, PKG_BAND, PKG_FACEBOOK, PKG_TWITTER};
    private static String[] SNS_PKG_LIST_LOCATION = {PKG_KAKAO, PKG_LINE};
    private static String[] SNS_PKG_LIST_RECOMMAND = {PKG_KAKAO, PKG_STORY, PKG_LINE, PKG_BAND, PKG_FACEBOOK, PKG_TWITTER};
    private static String[] SNS_PKG_LIST_SURVEY = {PKG_KAKAO, PKG_LINE};
    private static final String TITLE_ROUGH = "\uc5e0\ube0c\ub808\uc778 \uc624\uc2dc\ub294\uae38";
    private static final String TWITTER_LINK_URL = PanelApplication.EVENT_RECOMMEND_SHARE_BASE;
    public static String WEB_EVENT_SNS_URL = "/user/event/open/list?eventNo=";
    public static String WEB_SURVEY_SNS_URL = "/user/survey/offline/detail/";
    private static ResponseCallback kakaoCallback = new ResponseCallback<KakaoLinkResponse>() {
        public void onFailure(ErrorResult errorResult) {
            StringBuilder sb = new StringBuilder();
            sb.append("=========onFailure======");
            sb.append(errorResult.getErrorMessage());
            LogUtil.write(sb.toString());
        }

        public void onSuccess(KakaoLinkResponse kakaoLinkResponse) {
            StringBuilder sb = new StringBuilder();
            sb.append("=========onSuccess======");
            sb.append(kakaoLinkResponse.getArgumentMsg());
            LogUtil.write(sb.toString());
        }
    };

    public static class SNSInfo {
        Drawable mDrawable;
        String mPkgName;

        public SNSInfo(String str, Drawable drawable) {
            this.mPkgName = str;
            this.mDrawable = drawable;
        }

        public String getPackageName() {
            return this.mPkgName;
        }

        public Drawable getDrawable() {
            return this.mDrawable;
        }
    }

    private String appendUrlInfo(String str, Map<String, Object> map) {
        return str;
    }

    @NonNull
    private static String getRecommandMsg(@NonNull Context context) {
        UserInfo userInfo = UserInfoManager.getInstance(context).getUserInfo();
        return context.getString(R.string.share_recommand_msg, new Object[]{userInfo.getUserNm(), userInfo.getUser_id()});
    }

    @NonNull
    private static String getRecommandLinkText(@NonNull Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append(PanelApplication.EVENT_RECOMMEND_SHARE_BASE);
        sb.append("/user/main");
        return context.getString(R.string.share_recommand_link_text, new Object[]{sb.toString()});
    }

    static {
        StringBuilder sb = new StringBuilder();
        sb.append(WEB_SURVEY_SNS_URL);
        sb.append("line/");
        LINE_WEB_SURVEY_SNS_URL = sb.toString();
    }

    public static ArrayList<SNSInfo> installedSNSList(Context context, String str) {
        String[] packageArray;
        ArrayList<SNSInfo> arrayList = new ArrayList<>();
        PackageManager packageManager = context.getPackageManager();
        for (String str2 : getPackageArray(str)) {
            try {
                arrayList.add(new SNSInfo(str2, packageManager.getApplicationIcon(str2)));
            } catch (NameNotFoundException unused) {
            }
        }
        return arrayList;
    }

    private static String[] getPackageArray(String str) {
        if (ShareInfo.TYPE_SURVEY.equals(str)) {
            return SNS_PKG_LIST_SURVEY;
        }
        if ("event".equals(str)) {
            return SNS_PKG_LIST_EVENT;
        }
        if (ShareInfo.TYPE_RECOMMAND.equals(str)) {
            return SNS_PKG_LIST_RECOMMAND;
        }
        if ("location".equals(str)) {
            return SNS_PKG_LIST_LOCATION;
        }
        return new String[0];
    }

    public static void shareSNS(Context context, String str, ShareInfo shareInfo) {
        try {
            if (PKG_KAKAO.equals(str)) {
                shareKakao(context, shareInfo);
            } else if (PKG_STORY.equals(str)) {
                shareKakaoStory(context, shareInfo);
            } else if (PKG_LINE.equals(str)) {
                shareLine(context, shareInfo);
            } else if (PKG_BAND.equals(str)) {
                shareBand(context, shareInfo);
            } else if (PKG_FACEBOOK.equals(str)) {
                shareFacebook(context, shareInfo);
            } else if (PKG_TWITTER.equals(str)) {
                shareTwitter(context, shareInfo);
            } else if (SharePopup.PKG_SMS.equals(str)) {
                ShareSMS(context, shareInfo);
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append("\uc815\uc758\ub418\uc9c0 \uc54a\uc740 SNS \uc785\ub2c8\ub2e4. : ");
                sb.append(str);
                Toast.makeText(context, sb.toString(), 0).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, "\uc798\ubabb\ub41c \ub3d9\uc791\uc785\ub2c8\ub2e4.", 0).show();
        }
    }

    private static void shareKakao(Context context, ShareInfo shareInfo) {
        try {
            String str = shareInfo.title;
            String imageUrl = getImageUrl(shareInfo.imageId);
            StringBuilder sb = new StringBuilder();
            TemplateParams templateParams = null;
            if (ShareInfo.TYPE_RECOMMAND.equals(shareInfo.type)) {
                String recommandMsg = getRecommandMsg(context);
                Builder newBuilder = LinkObject.newBuilder();
                StringBuilder sb2 = new StringBuilder();
                sb2.append(KAKAO_LINK_URL);
                sb2.append("/user/main");
                Builder webUrl = newBuilder.setWebUrl(sb2.toString());
                StringBuilder sb3 = new StringBuilder();
                sb3.append(KAKAO_LINK_URL);
                sb3.append("/user/main");
                templateParams = TextTemplate.newBuilder(recommandMsg, webUrl.setMobileWebUrl(sb3.toString()).build()).setButtonTitle(DEFAULT_SHARE_BUTTON_TEXT).build();
            } else if ("event".equals(shareInfo.type)) {
                sb.append(KAKAO_LINK_URL);
                sb.append(WEB_EVENT_SNS_URL);
                sb.append(shareInfo.eventId);
                LinkObject build = LinkObject.newBuilder().setWebUrl(sb.toString()).setMobileWebUrl(sb.toString()).build();
                templateParams = FeedTemplate.newBuilder(ContentObject.newBuilder(str, imageUrl, build).build()).addButton(new ButtonObject(DEFAULT_SHARE_BUTTON_TEXT, build)).build();
            } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
                sb.append(KAKAO_LINK_URL);
                sb.append(WEB_SURVEY_SNS_URL);
                sb.append(shareInfo.eventId);
                LinkObject build2 = LinkObject.newBuilder().setWebUrl(sb.toString()).setMobileWebUrl(sb.toString()).build();
                templateParams = FeedTemplate.newBuilder(ContentObject.newBuilder(str, imageUrl, build2).build()).addButton(new ButtonObject(DEFAULT_SHARE_BUTTON_TEXT, build2)).build();
            } else if ("location".equals(shareInfo.type)) {
                templateParams = LocationTemplate.newBuilder("\uc11c\uc6b8\uc2dc \uac15\ub0a8\uad6c \uac15\ub0a8\ub300\ub85c 318", ContentObject.newBuilder(TITLE_ROUGH, PanelApplication.URL_ROUGH_MAP, LinkObject.newBuilder().setWebUrl(PanelApplication.URL_DIRECTION_LINK).setMobileWebUrl(PanelApplication.URL_DIRECTION_LINK).build()).setDescrption("\uc11c\uc6b8\uc2dc \uac15\ub0a8\uad6c \uac15\ub0a8\ub300\ub85c 318\n(\uc5ed\uc0bc\ub3d9, 837\ud0c0\uc6cc) 3~4\uce35, 10~14\uce35\n(3\uce35 \uce74\ud398\ud14c\ub9ac\uc544 / 10\uce35 \uc88c\ub2f4\ud68c\uc2e4)").setImageWidth(568).setImageHeight(478).build()).addButton(new ButtonObject("\uc5f0\uacb0", LinkObject.newBuilder().setWebUrl(PanelApplication.URL_DIRECTION_LINK).setMobileWebUrl(PanelApplication.URL_DIRECTION_LINK).build())).setAddressTitle("\uc5e0\ube0c\ub808\uc778 \ud328\ub110\ud30c\uc6cc").build();
            }
            KakaoLinkService.getInstance().sendDefault(context, templateParams, kakaoCallback);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void shareKakaoStory(Context context, ShareInfo shareInfo) {
        try {
            StringBuilder sb = new StringBuilder();
            if (ShareInfo.TYPE_RECOMMAND.equals(shareInfo.type)) {
                sb.append(getRecommandMsg(context));
                StringBuilder sb2 = new StringBuilder();
                sb2.append(KAKAO_STORY_LINK_URL);
                sb2.append("/user/main");
                sb.append(sb2.toString());
            } else if ("event".equals(shareInfo.type)) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append(shareInfo.title);
                sb3.append("\n");
                sb.append(sb3.toString());
                sb.append(KAKAO_STORY_LINK_URL);
                sb.append(WEB_EVENT_SNS_URL);
                sb.append(shareInfo.eventId);
            } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
                StringBuilder sb4 = new StringBuilder();
                sb4.append(shareInfo.title);
                sb4.append("\n");
                sb.append(sb4.toString());
                sb.append(KAKAO_STORY_LINK_URL);
                sb.append(WEB_SURVEY_SNS_URL);
                sb.append(shareInfo.eventId);
            }
            StringBuilder sb5 = new StringBuilder();
            sb5.append(BASE_KAKAO_STORY);
            StringBuilder sb6 = new StringBuilder();
            sb6.append("post=");
            sb6.append(URLEncoder.encode(sb.toString(), DEFAULT_ENCODING));
            sb5.append(sb6.toString());
            sb5.append(getEtcParam(context));
            StringBuilder sb7 = new StringBuilder();
            sb7.append("&urlinfo=");
            sb7.append(getUrlInfo(shareInfo.imageId, shareInfo.title));
            sb5.append(sb7.toString());
            context.startActivity(new Intent("android.intent.action.SEND", Uri.parse(sb5.toString())));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getEtcParam(Context context) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        sb.append("&appid=");
        sb.append(URLEncoder.encode(context.getPackageName(), DEFAULT_ENCODING));
        sb.append("&appver=");
        sb.append(URLEncoder.encode(DeviceUtils.getAppVersion(context), DEFAULT_ENCODING));
        sb.append("&apiver=");
        sb.append(URLEncoder.encode("1.0", DEFAULT_ENCODING));
        sb.append("&appname=");
        sb.append(URLEncoder.encode("\ud328\ub110\ud30c\uc6cc", DEFAULT_ENCODING));
        return sb.toString();
    }

    private static String getUrlInfo(String str, String str2) throws UnsupportedEncodingException {
        JsonObject jsonObject = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        jsonArray.add(getImageUrl(str));
        jsonObject.add("imageurl", jsonArray);
        jsonObject.addProperty((String) "type", (String) "article");
        jsonObject.addProperty((String) "title", str2);
        return URLEncoder.encode(jsonObject.toString(), DEFAULT_ENCODING);
    }

    private static String getImageUrl(String str) {
        if (StringUtils.isEmpty(str)) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("https://www.panel.co.kr/mobile/file/image?id=");
        sb.append(str);
        return sb.toString();
    }

    private static void shareLine(Context context, ShareInfo shareInfo) {
        String str = shareInfo.title;
        StringBuilder sb = new StringBuilder();
        if (ShareInfo.TYPE_RECOMMAND.equals(shareInfo.type)) {
            str = getRecommandMsg(context);
            sb.append(getRecommandLinkText(context));
        } else if ("event".equals(shareInfo.type)) {
            sb.append(LINE_LINK_URL);
            sb.append(WEB_EVENT_SNS_URL);
            sb.append(shareInfo.eventId);
        } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
            sb.append(LINE_LINK_URL);
            sb.append(LINE_WEB_SURVEY_SNS_URL);
            sb.append(shareInfo.eventId);
        } else if ("location".equals(shareInfo.type)) {
            sb.append(PanelApplication.URL_DIRECTION_LINK);
            str = TITLE_ROUGH;
        }
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setPackage(PKG_LINE);
        intent.setType("text/plain");
        StringBuilder sb2 = new StringBuilder();
        sb2.append(str);
        sb2.append("\n\n");
        sb2.append(sb.toString());
        intent.putExtra("android.intent.extra.TEXT", sb2.toString());
        context.startActivity(intent);
    }

    private static void shareBand(Context context, ShareInfo shareInfo) throws UnsupportedEncodingException {
        String str;
        StringBuilder sb = new StringBuilder();
        String str2 = "";
        if (ShareInfo.TYPE_RECOMMAND.equals(shareInfo.type)) {
            String recommandMsg = getRecommandMsg(context);
            StringBuilder sb2 = new StringBuilder();
            sb2.append(recommandMsg);
            sb2.append(getRecommandLinkText(context));
            str2 = sb2.toString();
            str = BAND_LINK_URL;
        } else if ("event".equals(shareInfo.type)) {
            sb.append(BAND_LINK_URL);
            sb.append(WEB_EVENT_SNS_URL);
            sb.append(shareInfo.eventId);
            StringBuilder sb3 = new StringBuilder();
            sb3.append(shareInfo.title);
            sb3.append("\n\n");
            sb3.append(sb.toString());
            str2 = URLEncoder.encode(sb3.toString(), DEFAULT_ENCODING);
            str = sb.toString();
        } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
            sb.append(BAND_LINK_URL);
            sb.append(WEB_SURVEY_SNS_URL);
            sb.append(shareInfo.eventId);
            StringBuilder sb4 = new StringBuilder();
            sb4.append(shareInfo.title);
            sb4.append("\n\n");
            sb4.append(sb.toString());
            str2 = URLEncoder.encode(sb4.toString(), DEFAULT_ENCODING);
            str = sb.toString();
        } else {
            str = str2;
        }
        StringBuilder sb5 = new StringBuilder();
        sb5.append("bandapp://create/post?text=");
        sb5.append(str2);
        sb5.append("&route=");
        sb5.append(str);
        context.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(sb5.toString())));
    }

    private static void shareFacebook(Context context, ShareInfo shareInfo) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(BASE_FACEBOOK);
            if (ShareInfo.TYPE_RECOMMAND.equals(shareInfo.type)) {
                sb.append("u=");
                StringBuilder sb2 = new StringBuilder();
                sb2.append(FACEBOOK_LINK_URL);
                sb2.append("/user/main");
                sb.append(URLEncoder.encode(sb2.toString(), DEFAULT_ENCODING));
                sb.append("&quote=");
                sb.append(URLEncoder.encode(getRecommandMsg(context), DEFAULT_ENCODING));
            } else if ("event".equals(shareInfo.type)) {
                sb.append("u=");
                StringBuilder sb3 = new StringBuilder();
                sb3.append(FACEBOOK_LINK_URL);
                sb3.append("/user/event/open/list/facebook?eventNo=");
                sb3.append(shareInfo.eventId);
                sb.append(URLEncoder.encode(sb3.toString(), DEFAULT_ENCODING));
                sb.append("&quote=");
                sb.append(URLEncoder.encode(shareInfo.title, DEFAULT_ENCODING));
            } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
                sb.append("u=");
                StringBuilder sb4 = new StringBuilder();
                sb4.append(FACEBOOK_LINK_URL);
                sb4.append(WEB_SURVEY_SNS_URL);
                sb4.append("facebook/");
                sb4.append(shareInfo.eventId);
                sb.append(URLEncoder.encode(sb4.toString(), DEFAULT_ENCODING));
                sb.append("&quote=");
                sb.append(URLEncoder.encode(shareInfo.title, DEFAULT_ENCODING));
            }
            context.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(sb.toString())));
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, R.string.share_failed_facebook, 0).show();
        }
    }

    private static void shareTwitter(Context context, ShareInfo shareInfo) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(BASE_TWITTER);
            if (ShareInfo.TYPE_RECOMMAND.equals(shareInfo.type)) {
                sb.append("text=");
                StringBuilder sb2 = new StringBuilder();
                sb2.append(getRecommandMsg(context));
                sb2.append(getRecommandLinkText(context));
                sb.append(URLEncoder.encode(sb2.toString(), DEFAULT_ENCODING));
            } else if ("event".equals(shareInfo.type)) {
                sb.append("text=");
                sb.append(shareInfo.title);
                sb.append("&url=");
                sb.append(TWITTER_LINK_URL);
                sb.append(WEB_EVENT_SNS_URL);
                sb.append(shareInfo.eventId);
            } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
                sb.append("text=");
                sb.append(shareInfo.title);
                sb.append("&url=");
                sb.append(TWITTER_LINK_URL);
                sb.append(WEB_SURVEY_SNS_URL);
                sb.append(shareInfo.eventId);
            }
            OtherPackageUtils.goBrowser(context, sb.toString());
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, R.string.share_failed_twitter, 0).show();
        }
    }

    private static void ShareSMS(Context context, ShareInfo shareInfo) {
        StringBuilder sb = new StringBuilder();
        if ("event".equals(shareInfo.type)) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(shareInfo.title);
            sb2.append("\n");
            sb.append(sb2.toString());
            sb.append(SMS_LINK_URL);
            sb.append(WEB_EVENT_SNS_URL);
            sb.append(shareInfo.eventId);
        } else if (ShareInfo.TYPE_SURVEY.equals(shareInfo.type)) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append(shareInfo.title);
            sb3.append("\n");
            sb.append(sb3.toString());
            sb.append(SMS_LINK_URL);
            sb.append(WEB_SURVEY_SNS_URL);
            sb.append(shareInfo.eventId);
        } else if ("location".equals(shareInfo.type)) {
            sb.append(TITLE_ROUGH);
            sb.append("\n");
            sb.append(PanelApplication.URL_DIRECTION_LINK);
        }
        Intent intent = new Intent("android.intent.action.SENDTO");
        intent.setData(Uri.parse("smsto:"));
        intent.putExtra("sms_body", sb.toString());
        context.startActivity(intent);
    }

    public static void postClipCopyBoard(Context context, Object obj) {
        ClipboardManager clipboardManager = (ClipboardManager) context.getSystemService("clipboard");
        StringBuilder sb = new StringBuilder();
        if (obj instanceof SurveyOfflineItemObj) {
            sb.append(PanelApplication.SERVICE_URL);
            sb.append("/survey/offline/detail/");
            sb.append(((SurveyOfflineItemObj) obj).srvNo);
        } else if (obj instanceof EventItemVO) {
            sb.append(PanelApplication.SERVICE_URL);
            sb.append(WEB_EVENT_SNS_URL);
            sb.append(((EventItemVO) obj).eventNo);
        }
        clipboardManager.setPrimaryClip(ClipData.newPlainText("label", sb.toString()));
        Toast.makeText(context, "\ubcf5\uc0ac\ub418\uc5c8\uc2b5\ub2c8\ub2e4.", 0).show();
    }
}