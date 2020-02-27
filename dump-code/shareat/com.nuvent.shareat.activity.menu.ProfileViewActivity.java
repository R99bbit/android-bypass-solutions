package com.nuvent.shareat.activity.menu;

import android.os.Bundle;
import android.widget.ImageView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import net.xenix.util.ImageDisplay;

public class ProfileViewActivity extends BaseActivity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_profile_viewer);
        ImageDisplay.getInstance().displayImageLoad(getIntent().getStringExtra("url"), (ImageView) findViewById(R.id.touchImageView));
    }
}