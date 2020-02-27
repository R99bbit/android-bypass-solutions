package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.intro.VersionCheckApi;
import com.nuvent.shareat.model.VersionModel;
import com.nuvent.shareat.util.GAEvent;

public class VersionInfoActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public String mUpdateUrl;

    public void onClickUpdate(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_version_info, (int) R.string.ga_ev_click, (int) R.string.ga_version_info_update);
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setData(Uri.parse(this.mUpdateUrl));
        startActivity(intent);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_version, 2);
        GAEvent.onGAScreenView(this, R.string.ga_version_info);
        showFavoriteButton(false);
        showSubActionbar();
        setTitle("\ubc84\uc804\uc815\ubcf4");
        findViewById(R.id.updateButton).setEnabled(false);
        ((TextView) findViewById(R.id.currentVersion)).setText(ShareatApp.getInstance().getAppVersionName());
        requestVersionCheckApi();
    }

    /* access modifiers changed from: private */
    public void requestVersionCheckApi() {
        VersionCheckApi request = new VersionCheckApi(this);
        request.addGetParam("?gubun=U");
        request.request(new RequestHandler() {
            public void onStart() {
                VersionInfoActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                VersionInfoActivity.this.showCircleDialog(false);
                VersionModel model = (VersionModel) result;
                VersionInfoActivity.this.mUpdateUrl = model.getUrl();
                ((TextView) VersionInfoActivity.this.findViewById(R.id.newVersion)).setText(model.getVersion());
                VersionInfoActivity.this.setUpdateStatus(model.getVersion());
            }

            public void onFailure(Exception exception) {
                VersionInfoActivity.this.showCircleDialog(false);
                VersionInfoActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        VersionInfoActivity.this.requestVersionCheckApi();
                    }
                });
            }

            public void onFinish() {
                VersionInfoActivity.this.showCircleDialog(false);
            }
        });
    }

    /* access modifiers changed from: private */
    public void setUpdateStatus(String newVersion) {
        boolean isUpdate;
        String currentVersion = ShareatApp.getInstance().getAppVersionName();
        String[] newVersionNameSplit = newVersion.split("\\.");
        String[] currentVersionSplit = currentVersion.split("\\.");
        int appMajorVersion = Integer.valueOf(currentVersionSplit[0]).intValue();
        int appMinorVersion = Integer.valueOf(currentVersionSplit[1]).intValue();
        int appPatchVersion = Integer.valueOf(currentVersionSplit[2]).intValue();
        int serverMajorVersion = Integer.valueOf(newVersionNameSplit[0]).intValue();
        int serverMinorVersion = Integer.valueOf(newVersionNameSplit[1]).intValue();
        int serverPatchVersion = Integer.valueOf(newVersionNameSplit[2]).intValue();
        if (appMajorVersion < serverMajorVersion) {
            isUpdate = true;
        } else if (appMajorVersion == serverMajorVersion && appMinorVersion < serverMinorVersion) {
            isUpdate = true;
        } else if (appMajorVersion == serverMajorVersion && appMinorVersion == serverMinorVersion && appPatchVersion < serverPatchVersion) {
            isUpdate = true;
        } else {
            isUpdate = false;
        }
        findViewById(R.id.updateButton).setEnabled(isUpdate);
    }
}