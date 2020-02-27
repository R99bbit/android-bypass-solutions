package com.nuvent.shareat.activity.common;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.menu.InquiryActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.util.GAEvent;

public class PostWebViewActivity extends MainActionBarActivity {
    private final String WEBVIEW_TYPE_EVENT = "webview";
    private final String WEBVIEW_TYPE_FAQ = "board_FAQ";
    private final String WEBVIEW_TYPE_NOTICE = "board_Noti";

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        String replace;
        String replace2;
        String replace3;
        super.onCreate(savedInstanceState);
        if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_URL)) {
            String path = Uri.parse(getIntent().getStringExtra(CustomSchemeManager.EXTRA_INTENT_URL)).getPath();
            String boardUrl = null;
            if (path.startsWith("/")) {
                path = path.replaceFirst("/", "");
            }
            String[] segment = path.split("/");
            if (getIntent().hasExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER)) {
                boardUrl = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER).getString("board_url", "");
            }
            if (segment[0].equals("board_FAQ")) {
                GAEvent.onGAScreenView(this, R.string.ga_faq_board);
                Intent putExtra = new Intent(this, WebViewActivity.class).putExtra("title", "\uc790\uc8fc\ubb3b\ub294\uc9c8\ubb38");
                if (boardUrl == null) {
                    replace3 = String.format(ApiUrl.FAQ_URL, new Object[]{SessionManager.getInstance().getAuthToken()});
                } else {
                    replace3 = boardUrl.replace("$auth_token", SessionManager.getInstance().getAuthToken());
                }
                pushActivity(putExtra.putExtra("url", replace3));
            } else if (segment[0].equals("board_Noti")) {
                GAEvent.onGAScreenView(this, R.string.ga_notice_board);
                Intent putExtra2 = new Intent(this, WebViewActivity.class).putExtra("title", "\uacf5\uc9c0\uc0ac\ud56d");
                if (boardUrl == null) {
                    replace2 = String.format(ApiUrl.NOTICE_URL, new Object[]{SessionManager.getInstance().getAuthToken()});
                } else {
                    replace2 = boardUrl.replace("$auth_token", SessionManager.getInstance().getAuthToken());
                }
                pushActivity(putExtra2.putExtra("url", replace2));
            } else {
                Intent intent = new Intent(this, InquiryActivity.class);
                if (boardUrl == null) {
                    replace = String.format(ApiUrl.QNA_URL, new Object[]{SessionManager.getInstance().getAuthToken()});
                } else {
                    replace = boardUrl.replace("$auth_token", SessionManager.getInstance().getAuthToken());
                }
                pushActivity(intent.putExtra("url", replace));
            }
            finish(false);
        }
    }
}