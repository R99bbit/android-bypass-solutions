package com.nuvent.shareat.manager;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.event.SchemeMainlistEvent;
import com.nuvent.shareat.fragment.StoreDetailFragment;
import com.nuvent.shareat.manager.app.SessionManager;
import de.greenrobot.event.EventBus;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class CustomSchemeManager {
    public static final String EXTRA_INTENT_PARAMETER = "parameter";
    public static final String EXTRA_INTENT_SUB_TAB_NAME = "subTabName";
    public static final String EXTRA_INTENT_URL = "customURL";
    public static final String HOST_NAME = "shareat.me/";
    public static final String SCHEME_NAME = "shareat";

    public static void postSchemeAction(Context context, String customSchemeUrl) {
        if (customSchemeUrl.startsWith("shareat://shareat.me/")) {
            try {
                Uri receiveUrl = Uri.parse(customSchemeUrl);
                String path = receiveUrl.getPath();
                String queryString = receiveUrl.getEncodedQuery();
                if (path.startsWith("/")) {
                    path = path.replaceFirst("/", "");
                }
                if (path.equals("mainlist") || path.equals(StoreDetailFragment.SUB_TAB_NAME_PAYMENT)) {
                    if (queryString != null && !queryString.isEmpty()) {
                        Bundle bundle = getQueryBundle(queryString);
                        if (path.equals(StoreDetailFragment.SUB_TAB_NAME_PAYMENT)) {
                            ((MainActivity) context).onQuickPayStore(bundle.getString("partner_sno"));
                        } else {
                            EventBus.getDefault().post(new SchemeMainlistEvent(bundle));
                        }
                    }
                } else if (path.equals("appstore")) {
                    Intent intent = new Intent("android.intent.action.VIEW");
                    intent.setData(Uri.parse("market://details?id=" + context.getPackageName()));
                    context.startActivity(intent);
                } else {
                    String[] segment = path.split("/");
                    Intent intent2 = new Intent("android.intent.action." + segment[0]);
                    intent2.putExtra(EXTRA_INTENT_URL, customSchemeUrl);
                    if (queryString != null) {
                        intent2.putExtra(EXTRA_INTENT_PARAMETER, getQueryBundle(queryString));
                    }
                    if (1 < segment.length) {
                        intent2.putExtra(EXTRA_INTENT_SUB_TAB_NAME, segment[1]);
                    }
                    if (segment[0].equals("usage")) {
                        intent2.putExtra("menuRequest", "");
                    }
                    if (segment[0].equals(StoreDetailFragment.SUB_TAB_NAME_REVIEW)) {
                        ((BaseActivity) context).modalActivity(intent2);
                    } else {
                        ((BaseActivity) context).pushActivity(intent2);
                    }
                }
            } catch (StringIndexOutOfBoundsException e) {
                e.printStackTrace();
            } catch (NullPointerException e2) {
                e2.printStackTrace();
            } catch (Exception e3) {
                e3.printStackTrace();
            }
        }
    }

    public static Bundle getQueryBundle(String query) {
        String[] params = query.split("&");
        Bundle data = new Bundle();
        for (String param : params) {
            String name = param.split("=")[0];
            try {
                String decodeValue = URLDecoder.decode(param.split("=")[1], "UTF-8");
                if (decodeValue.trim().equals("$auth_token")) {
                    decodeValue = SessionManager.getInstance().getAuthToken();
                } else if (decodeValue.trim().equals("$user_sno")) {
                    decodeValue = ShareatApp.getInstance().getUserNum();
                }
                data.putString(name, decodeValue);
            } catch (ArrayIndexOutOfBoundsException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e2) {
                e2.printStackTrace();
            }
        }
        return data;
    }
}