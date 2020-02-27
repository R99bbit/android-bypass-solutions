package com.nuvent.shareat.activity.common;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.fragment.WebViewFragment;

public class WebViewActivity extends MainActionBarActivity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_webview, 2);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle(getIntent().getStringExtra("title"));
        WebViewFragment webViewFragment = new WebViewFragment();
        if (getIntent().hasExtra("url")) {
            webViewFragment.setUrl(getIntent().getStringExtra("url"));
        }
        getSupportFragmentManager().beginTransaction().add((int) R.id.containerLayout, (Fragment) webViewFragment).commit();
    }
}