package com.plengi.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends Activity {
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = getIntent();
        if (intent != null) {
            "com.loplat.placeengine.MAIN".equals(intent.getAction());
        }
        finish();
    }
}