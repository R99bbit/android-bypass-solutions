package com.nuvent.shareat.manager.sns;

import android.app.Activity;
import android.os.Bundle;
import com.facebook.AccessToken;
import com.facebook.CallbackManager;
import com.facebook.FacebookCallback;
import com.facebook.FacebookException;
import com.facebook.GraphRequest;
import com.facebook.GraphRequest.GraphJSONObjectCallback;
import com.facebook.GraphResponse;
import com.facebook.login.LoginManager;
import com.facebook.login.LoginResult;
import com.nuvent.shareat.model.SnsModel;
import java.util.Arrays;
import org.json.JSONException;
import org.json.JSONObject;

public class FacebookLoginManager extends BaseSnsManager {
    private Activity mActivity;
    private CallbackManager mManager;

    public FacebookLoginManager(Activity activity, CallbackManager manager) {
        this.mActivity = activity;
        this.mManager = manager;
    }

    /* access modifiers changed from: private */
    public void requestFacebookLogin() {
        LoginManager.getInstance().logInWithReadPermissions(this.mActivity, Arrays.asList(new String[]{"public_profile", "email"}));
        LoginManager.getInstance().registerCallback(this.mManager, new FacebookCallback<LoginResult>() {
            public void onSuccess(LoginResult loginResults) {
                GraphRequest request = GraphRequest.newMeRequest(loginResults.getAccessToken(), new GraphJSONObjectCallback() {
                    public void onCompleted(JSONObject object, GraphResponse response) {
                        if (object != null) {
                            try {
                                if (object.has("email") && !object.getString("email").isEmpty()) {
                                    SnsModel model = new SnsModel();
                                    model.setAccessToken(response.getRequest().getAccessToken().getToken());
                                    model.setSNSID(object.getString("id"));
                                    model.setUserEmail(object.getString("email"));
                                    model.setUserName(object.getString("name"));
                                    model.setAvatarImageUrl("http://graph.facebook.com/" + model.getSNSID() + "/picture?type=large");
                                    FacebookLoginManager.this.mListener.onCompleted(model, BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK);
                                    return;
                                }
                            } catch (JSONException e) {
                                e.printStackTrace();
                                return;
                            }
                        }
                        FacebookLoginManager.this.mListener.onError(new Exception("\uc774\uba54\uc77c\uc774 \ub4f1\ub85d\ub41c \ud398\uc774\uc2a4\ubd81 \uc544\uc774\ub514\ub9cc \uac00\uc785\uc774 \uac00\ub2a5\ud569\ub2c8\ub2e4."), BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK);
                    }
                });
                Bundle parameters = new Bundle();
                parameters.putString("fields", "id,name,email,gender,birthday");
                request.setParameters(parameters);
                request.executeAsync();
            }

            public void onCancel() {
                FacebookLoginManager.this.mListener.onError(new Exception("\ud398\uc774\uc2a4\ubd81 \ub85c\uadf8\uc778\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4. \ub2e4\uc2dc \ub85c\uadf8\uc778\ud574\uc8fc\uc138\uc694."), BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK);
            }

            public void onError(FacebookException e) {
                e.printStackTrace();
                FacebookLoginManager.this.mListener.onError(new Exception("\ud398\uc774\uc2a4\ubd81 \ub85c\uadf8\uc778\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4. \ub2e4\uc2dc \ub85c\uadf8\uc778\ud574\uc8fc\uc138\uc694."), BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK);
            }
        });
    }

    public void requestFacebookGraphApi() {
        if (AccessToken.getCurrentAccessToken() == null || AccessToken.getCurrentAccessToken().getToken() == null || AccessToken.getCurrentAccessToken().getToken().isEmpty()) {
            requestFacebookLogin();
            return;
        }
        GraphRequest request = GraphRequest.newMeRequest(AccessToken.getCurrentAccessToken(), new GraphJSONObjectCallback() {
            public void onCompleted(JSONObject object, GraphResponse response) {
                if (object == null) {
                    try {
                        LoginManager.getInstance().logOut();
                        FacebookLoginManager.this.requestFacebookLogin();
                    } catch (JSONException e) {
                        e.printStackTrace();
                        LoginManager.getInstance().logOut();
                        FacebookLoginManager.this.requestFacebookLogin();
                    }
                } else if (!object.has("email") || object.getString("email").isEmpty()) {
                    FacebookLoginManager.this.mListener.onError(new Exception("\uc774\uba54\uc77c\uc774 \ub4f1\ub85d\ub41c \ud398\uc774\uc2a4\ubd81 \uc544\uc774\ub514\ub9cc \uac00\uc785\uc774 \uac00\ub2a5\ud569\ub2c8\ub2e4."), BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK);
                } else {
                    SnsModel model = new SnsModel();
                    model.setAccessToken(response.getRequest().getAccessToken().getToken());
                    model.setSNSID(object.getString("id"));
                    model.setUserEmail(object.getString("email"));
                    model.setUserName(object.getString("name"));
                    model.setAvatarImageUrl("http://graph.facebook.com/" + model.getSNSID() + "/picture?type=large");
                    FacebookLoginManager.this.mListener.onCompleted(model, BaseSnsManager.SNS_LOGIN_TYPE_FACEBOOK);
                }
            }
        });
        Bundle parameters = new Bundle();
        parameters.putString("fields", "id,name,email,gender, birthday");
        request.setParameters(parameters);
        request.executeAsync();
    }
}