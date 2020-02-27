package com.gun0912.tedpermission;

import android.content.Context;
import android.content.Intent;
import android.os.Build.VERSION;
import android.support.annotation.StringRes;
import com.gun0912.tedpermission.PermissionBuilder;
import com.gun0912.tedpermission.util.ObjectUtils;

public abstract class PermissionBuilder<T extends PermissionBuilder> {
    private static final String PREFS_IS_FIRST_REQUEST = "PREFS_IS_FIRST_REQUEST";
    private static final String PREFS_NAME_PERMISSION = "PREFS_NAME_PERMISSION";
    private Context context;
    private CharSequence deniedCloseButtonText;
    private CharSequence denyMessage;
    private CharSequence denyTitle;
    private boolean hasSettingBtn = true;
    private PermissionListener listener;
    private String[] permissions;
    private CharSequence rationaleConfirmText;
    private CharSequence rationaleMessage;
    private CharSequence rationaleTitle;
    private int requestedOrientation;
    private CharSequence settingButtonText;

    public PermissionBuilder(Context context2) {
        this.context = context2;
        this.deniedCloseButtonText = context2.getString(R.string.tedpermission_close);
        this.rationaleConfirmText = context2.getString(R.string.tedpermission_confirm);
        this.requestedOrientation = -1;
    }

    /* access modifiers changed from: protected */
    public void checkPermissions() {
        if (this.listener == null) {
            throw new IllegalArgumentException("You must setPermissionListener() on TedPermission");
        } else if (ObjectUtils.isEmpty(this.permissions)) {
            throw new IllegalArgumentException("You must setPermissions() on TedPermission");
        } else if (VERSION.SDK_INT < 23) {
            this.listener.onPermissionGranted();
        } else {
            Intent intent = new Intent(this.context, TedPermissionActivity.class);
            intent.putExtra("permissions", this.permissions);
            intent.putExtra(TedPermissionActivity.EXTRA_RATIONALE_TITLE, this.rationaleTitle);
            intent.putExtra(TedPermissionActivity.EXTRA_RATIONALE_MESSAGE, this.rationaleMessage);
            intent.putExtra(TedPermissionActivity.EXTRA_DENY_TITLE, this.denyTitle);
            intent.putExtra(TedPermissionActivity.EXTRA_DENY_MESSAGE, this.denyMessage);
            intent.putExtra(TedPermissionActivity.EXTRA_PACKAGE_NAME, this.context.getPackageName());
            intent.putExtra(TedPermissionActivity.EXTRA_SETTING_BUTTON, this.hasSettingBtn);
            intent.putExtra(TedPermissionActivity.EXTRA_DENIED_DIALOG_CLOSE_TEXT, this.deniedCloseButtonText);
            intent.putExtra(TedPermissionActivity.EXTRA_RATIONALE_CONFIRM_TEXT, this.rationaleConfirmText);
            intent.putExtra(TedPermissionActivity.EXTRA_SETTING_BUTTON_TEXT, this.settingButtonText);
            intent.putExtra(TedPermissionActivity.EXTRA_SCREEN_ORIENTATION, this.requestedOrientation);
            intent.addFlags(268435456);
            intent.addFlags(262144);
            TedPermissionActivity.startActivity(this.context, intent, this.listener);
            TedPermissionBase.setFirstRequest(this.context, this.permissions);
        }
    }

    public T setPermissionListener(PermissionListener listener2) {
        this.listener = listener2;
        return this;
    }

    public T setPermissions(String... permissions2) {
        this.permissions = permissions2;
        return this;
    }

    public T setRationaleMessage(@StringRes int stringRes) {
        return setRationaleMessage(getText(stringRes));
    }

    private CharSequence getText(@StringRes int stringRes) {
        if (stringRes > 0) {
            return this.context.getText(stringRes);
        }
        throw new IllegalArgumentException("Invalid String resource id");
    }

    public T setRationaleMessage(CharSequence rationaleMessage2) {
        this.rationaleMessage = rationaleMessage2;
        return this;
    }

    public T setRationaleTitle(@StringRes int stringRes) {
        return setRationaleTitle(getText(stringRes));
    }

    public T setRationaleTitle(CharSequence rationaleMessage2) {
        this.rationaleTitle = rationaleMessage2;
        return this;
    }

    public T setDeniedMessage(@StringRes int stringRes) {
        return setDeniedMessage(getText(stringRes));
    }

    public T setDeniedMessage(CharSequence denyMessage2) {
        this.denyMessage = denyMessage2;
        return this;
    }

    public T setDeniedTitle(@StringRes int stringRes) {
        return setDeniedTitle(getText(stringRes));
    }

    public T setDeniedTitle(CharSequence denyTitle2) {
        this.denyTitle = denyTitle2;
        return this;
    }

    public T setGotoSettingButton(boolean hasSettingBtn2) {
        this.hasSettingBtn = hasSettingBtn2;
        return this;
    }

    public T setGotoSettingButtonText(@StringRes int stringRes) {
        return setGotoSettingButtonText(getText(stringRes));
    }

    public T setGotoSettingButtonText(CharSequence rationaleConfirmText2) {
        this.settingButtonText = rationaleConfirmText2;
        return this;
    }

    public T setRationaleConfirmText(@StringRes int stringRes) {
        return setRationaleConfirmText(getText(stringRes));
    }

    public T setRationaleConfirmText(CharSequence rationaleConfirmText2) {
        this.rationaleConfirmText = rationaleConfirmText2;
        return this;
    }

    public T setDeniedCloseButtonText(CharSequence deniedCloseButtonText2) {
        this.deniedCloseButtonText = deniedCloseButtonText2;
        return this;
    }

    public T setDeniedCloseButtonText(@StringRes int stringRes) {
        return setDeniedCloseButtonText(getText(stringRes));
    }

    public T setScreenOrientation(int requestedOrientation2) {
        this.requestedOrientation = requestedOrientation2;
        return this;
    }
}