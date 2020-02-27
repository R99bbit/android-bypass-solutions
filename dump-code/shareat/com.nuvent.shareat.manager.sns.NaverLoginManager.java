package com.nuvent.shareat.manager.sns;

import android.app.Activity;
import android.content.Context;
import android.os.AsyncTask;
import com.kakao.auth.helper.ServerProtocol;
import com.nhn.android.naverlogin.OAuthLogin;
import com.nhn.android.naverlogin.OAuthLoginHandler;
import com.nhn.android.naverlogin.connection.CommonConnection;
import com.nhn.android.naverlogin.connection.ResponseData;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.model.SnsModel;
import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.util.Iterator;
import javax.xml.parsers.DocumentBuilderFactory;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class NaverLoginManager extends BaseSnsManager {
    public static final String DEFAULT_NICK_NAME = "";
    /* access modifiers changed from: private */
    public Activity mActivity;
    private OAuthLoginHandler mNaverSessionCallback = new OAuthLoginHandler() {
        public void run(boolean success) {
            if (success) {
                NaverLoginManager.this.requestUserId();
            } else if (NaverLoginManager.this.mOAuthLoginInstance.getLastErrorCode(NaverLoginManager.this.mActivity).getCode().compareToIgnoreCase("user_cancel") != 0) {
                NaverLoginManager.this.mListener.onError(new Exception(NaverLoginManager.this.mActivity.getResources().getString(R.string.NAVER_LOGIN_ALERT_01)), BaseSnsManager.SNS_LOGIN_TYPE_NAVER);
            }
        }
    };
    /* access modifiers changed from: private */
    public OAuthLogin mOAuthLoginInstance;

    private class RequestApiReprompt extends AsyncTask<Void, Void, String> {
        private RequestApiReprompt() {
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
            try {
                ((BaseActivity) NaverLoginManager.this.mActivity).showLoadingDialog(true);
            } catch (Exception e) {
            }
        }

        /* access modifiers changed from: protected */
        public String doInBackground(Void... params) {
            String clientID = NaverLoginManager.this.mActivity.getResources().getString(R.string.naver_oauth_id);
            String clientSID = NaverLoginManager.this.mActivity.getResources().getString(R.string.naver_oauth_secret);
            String at = NaverLoginManager.this.mOAuthLoginInstance.getAccessToken(NaverLoginManager.this.mActivity);
            try {
                at = URLEncoder.encode(at, "UTF-8");
            } catch (Exception e) {
                e.printStackTrace();
            }
            ResponseData res = CommonConnection.request((Context) NaverLoginManager.this.mActivity, "https://nid.naver.com/oauth2.0/token" + String.format("?grant_type=delete&client_id=%s&client_secret=%s&access_token=%s&service_provider=NAVER", new Object[]{clientID, clientSID, at}), (String) null, (String) null, (String) null);
            if (res == null) {
                return null;
            }
            return res.mContent;
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(String content) {
            ((BaseActivity) NaverLoginManager.this.mActivity).showLoadingDialog(false);
            try {
                JSONObject jsonObj = new JSONObject(content);
                Iterator it = jsonObj.keys();
                String result = null;
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    String value = jsonObj.getString(key);
                    if (key.equalsIgnoreCase("result")) {
                        result = value;
                        break;
                    }
                }
                if (result != null) {
                    NaverLoginManager.this.mOAuthLoginInstance.logout(NaverLoginManager.this.mActivity);
                    NaverLoginManager.this.mListener.onErrorNaverReAgree(new Runnable() {
                        public void run() {
                        }
                    }, new Runnable() {
                        public void run() {
                            NaverLoginManager.this.mListener.onError(new Exception(NaverLoginManager.this.mActivity.getResources().getString(R.string.NAVER_LOGIN_ALERT_01)), BaseSnsManager.SNS_LOGIN_TYPE_NAVER);
                        }
                    });
                    return;
                }
                NaverLoginManager.this.mListener.onError(new Exception(NaverLoginManager.this.mActivity.getResources().getString(R.string.NAVER_LOGIN_ALERT_01)), BaseSnsManager.SNS_LOGIN_TYPE_NAVER);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class RequestApiTask extends AsyncTask<Void, Void, String> {
        private RequestApiTask() {
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
            try {
                ((BaseActivity) NaverLoginManager.this.mActivity).showLoadingDialog(true);
            } catch (Exception e) {
            }
        }

        /* access modifiers changed from: protected */
        public String doInBackground(Void... params) {
            return NaverLoginManager.this.mOAuthLoginInstance.requestApi(NaverLoginManager.this.mActivity, NaverLoginManager.this.mOAuthLoginInstance.getAccessToken(NaverLoginManager.this.mActivity), ApiUrl.NAVER_PROFILE);
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(String content) {
            ((BaseActivity) NaverLoginManager.this.mActivity).showLoadingDialog(false);
            try {
                Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(content.getBytes("UTF-8")));
                doc.getDocumentElement().normalize();
                if (doc.getElementsByTagName("resultcode").item(0).getTextContent().compareToIgnoreCase("00") == 0) {
                    Element response = (Element) doc.getElementsByTagName("response").item(0);
                    String email = response.getElementsByTagName("email").item(0).getTextContent();
                    String nickname = response.getElementsByTagName(ServerProtocol.NICK_NAME_KEY).item(0).getTextContent();
                    String enc_id = response.getElementsByTagName("enc_id").item(0).getTextContent();
                    String profile_image = response.getElementsByTagName(ServerProtocol.PROFILE_IMAGE_KEY).item(0).getTextContent();
                    SnsModel model = new SnsModel();
                    if (nickname == null || nickname.isEmpty()) {
                        nickname = "";
                    }
                    model.setUserName(nickname);
                    model.setAvatarImageUrl(profile_image);
                    model.setSNSID(enc_id);
                    model.setAccessToken(NaverLoginManager.this.mOAuthLoginInstance.getAccessToken(NaverLoginManager.this.mActivity));
                    model.setUserEmail(email);
                    NaverLoginManager.this.mListener.onCompleted(model, BaseSnsManager.SNS_LOGIN_TYPE_NAVER);
                    return;
                }
                NaverLoginManager.this.mListener.onError(new Exception(NaverLoginManager.this.mActivity.getResources().getString(R.string.NAVER_LOGIN_ALERT_01)), BaseSnsManager.SNS_LOGIN_TYPE_NAVER);
            } catch (Exception e) {
                e.printStackTrace();
                NaverLoginManager.this.requestUserRePrompt();
            }
        }
    }

    public NaverLoginManager(Activity activity) {
        this.mActivity = activity;
        this.mOAuthLoginInstance = OAuthLogin.getInstance();
        this.mOAuthLoginInstance.init(activity, activity.getResources().getString(R.string.naver_oauth_id), activity.getResources().getString(R.string.naver_oauth_secret), activity.getResources().getString(R.string.naver_oauth_app_name), activity.getResources().getString(R.string.naver_oauth_callback_url));
    }

    public void requestNaverSession() {
        this.mOAuthLoginInstance.startOauthLoginActivity(this.mActivity, this.mNaverSessionCallback);
    }

    /* access modifiers changed from: private */
    public void requestUserId() {
        new RequestApiTask().execute(new Void[0]);
    }

    /* access modifiers changed from: private */
    public void requestUserRePrompt() {
        new RequestApiReprompt().execute(new Void[0]);
    }
}