package com.embrain.panelpower;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.embrain.panelbigdata.utils.DeviceUtils;
import com.embrain.panelbigdata.utils.StringUtils;
import com.embrain.panelpower.habit_signal.HabitSignalManager;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.vo.AgreeCallVo;
import com.embrain.panelpower.networks.vo.AgreeEmailVo;
import com.embrain.panelpower.networks.vo.AgreeLocationVo;
import com.embrain.panelpower.networks.vo.AgreeMobileVo;
import com.embrain.panelpower.networks.vo.AgreePayVo;
import com.embrain.panelpower.networks.vo.AgreePushVo;
import com.embrain.panelpower.networks.vo.AgreeUsageVo;
import com.embrain.panelpower.networks.vo.AppVersionVO;
import com.embrain.panelpower.networks.vo.LoginVo;
import com.embrain.panelpower.networks.vo.MyInfoVo;
import com.embrain.panelpower.networks.vo.PanelBasicResponse;
import com.embrain.panelpower.networks.vo.ResponseCheckAppVersion;
import com.embrain.panelpower.networks.vo.ResponseLogin;
import com.embrain.panelpower.networks.vo.ResponseMyInfo;
import com.embrain.panelpower.utils.OtherPackageUtils;
import com.embrain.panelpower.views.PanelDialog;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack.RESULT_CODE;
import com.embrain.panelpower.vo.MyInfo;
import com.embrain.panelpower.vo.UserSession;
import com.google.gson.Gson;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class PanelSettingsActivity extends AppCompatActivity {
    /* access modifiers changed from: private */
    public String agree = "";
    /* access modifiers changed from: private */
    public Callback mAgreeCallback = new Callback() {
        public void onResponse(Call call, Response response) throws IOException {
            try {
                if (((PanelBasicResponse) new Gson().fromJson(response.body().string(), PanelBasicResponse.class)).isSuccess()) {
                    switch (PanelSettingsActivity.this.req_type) {
                        case 1:
                            UserInfoManager.setAgreePush(PanelSettingsActivity.this.getApplicationContext(), PanelSettingsActivity.this.agree);
                            PanelSettingsActivity.this.setToggle(DeviceUtils.hasPushPermission(PanelSettingsActivity.this.getBaseContext()), PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_push), PanelSettingsActivity.this.findViewById(R.id.cau_body_push));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_push);
                            break;
                        case 2:
                            PanelSettingsActivity.this.setToggle(true, PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_email), PanelSettingsActivity.this.findViewById(R.id.cau_body_email));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_email);
                            break;
                        case 3:
                            PanelSettingsActivity.this.setToggle(true, PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_mobile), PanelSettingsActivity.this.findViewById(R.id.cau_body_mobile));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_mobile);
                            break;
                        case 4:
                            PanelSettingsActivity.this.setToggle(true, PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_call), PanelSettingsActivity.this.findViewById(R.id.cau_body_call));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_call);
                            break;
                        case 5:
                            UserInfoManager.setAgreeLocation(PanelSettingsActivity.this.getApplicationContext(), PanelSettingsActivity.this.agree);
                            PanelSettingsActivity.this.setToggle(DeviceUtils.hasLocationPermission(PanelSettingsActivity.this.getBaseContext()), PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_location), PanelSettingsActivity.this.findViewById(R.id.cau_body_location));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_location);
                            break;
                        case 6:
                            UserInfoManager.setAgreeUsage(PanelSettingsActivity.this.getApplicationContext(), PanelSettingsActivity.this.agree);
                            PanelSettingsActivity.this.setToggle(DeviceUtils.hasUsagePermission(PanelSettingsActivity.this.getBaseContext()), PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_app_usage), PanelSettingsActivity.this.findViewById(R.id.cau_body_usage));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_usage);
                            break;
                        case 7:
                            UserInfoManager.setAgreePay(PanelSettingsActivity.this.getApplicationContext(), PanelSettingsActivity.this.agree);
                            PanelSettingsActivity.this.setToggle(HabitSignalManager.hasNotificationAccess(PanelSettingsActivity.this.getBaseContext()), PanelSettingsActivity.this.agree, PanelSettingsActivity.this.findViewById(R.id.btn_pay), PanelSettingsActivity.this.findViewById(R.id.cau_body_pay));
                            PanelSettingsActivity.this.showToast((int) R.string.settings_toast_change_pay);
                            break;
                    }
                } else {
                    PanelSettingsActivity.this.showPopup((int) R.string.settings_dialog_agree_failed);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Throwable th) {
                PanelSettingsActivity.this.req_type = -1;
                PanelSettingsActivity.this.reqStr = "";
                PanelSettingsActivity.this.agree = "";
                throw th;
            }
            PanelSettingsActivity.this.req_type = -1;
            PanelSettingsActivity.this.reqStr = "";
            PanelSettingsActivity.this.agree = "";
        }

        public void onFailure(Call call, IOException iOException) {
            PanelSettingsActivity.this.showPopup((int) R.string.settings_dialog_agree_failed);
            PanelSettingsActivity.this.req_type = -1;
            PanelSettingsActivity.this.reqStr = "";
            PanelSettingsActivity.this.agree = "";
        }
    };
    /* access modifiers changed from: private */
    public View mBodyAgree;
    /* access modifiers changed from: private */
    public View mBodyData;
    /* access modifiers changed from: private */
    public View mBodyPush;
    private OnClickListener mClick = new OnClickListener() {
        public void onClick(View view) {
            switch (view.getId()) {
                case R.id.btn_access_term /*2131296339*/:
                    OtherPackageUtils.goBrowser(PanelSettingsActivity.this.getBaseContext(), PanelApplication.URL_ACCESS_TERMS);
                    return;
                case R.id.btn_agree_call /*2131296340*/:
                case R.id.btn_agree_email /*2131296341*/:
                case R.id.btn_agree_mobile /*2131296342*/:
                case R.id.btn_agree_push /*2131296343*/:
                case R.id.btn_app_usage /*2131296344*/:
                case R.id.btn_location /*2131296351*/:
                case R.id.btn_pay /*2131296352*/:
                    PanelSettingsActivity.this.agree(view.getId());
                    return;
                case R.id.btn_back /*2131296345*/:
                    PanelSettingsActivity.this.onBackPressed();
                    return;
                case R.id.btn_direction /*2131296350*/:
                    PanelSettingsActivity.this.callPopupBrowser(PanelApplication.URL_DIRECTION);
                    return;
                case R.id.btn_privacy_policy /*2131296353*/:
                    OtherPackageUtils.goBrowser(PanelSettingsActivity.this.getBaseContext(), PanelApplication.URL_PRIVACY_POLICY);
                    return;
                default:
                    return;
            }
        }
    };
    private Callback mLoginCallback = new Callback() {
        public void onFailure(Call call, IOException iOException) {
            PanelSettingsActivity.this.showToast((int) R.string.settings_err_network_my_info);
            PanelSettingsActivity.this.hideLoading();
        }

        public void onResponse(Call call, Response response) throws IOException {
            try {
                ResponseLogin responseLogin = (ResponseLogin) new Gson().fromJson(response.body().string(), ResponseLogin.class);
                if (responseLogin.isSuccess()) {
                    PanelSettingsActivity.this.setUIUserInfo(responseLogin.getSession());
                    return;
                }
                PanelSettingsActivity.this.showToast((int) R.string.settings_err_my_info);
                PanelSettingsActivity.this.hideLoading();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };
    /* access modifiers changed from: private */
    public Callback mMyInfoCallback = new Callback() {
        public void onFailure(Call call, IOException iOException) {
            PanelSettingsActivity.this.showToast((int) R.string.settings_err_network_my_info);
            PanelSettingsActivity.this.hideLoading();
        }

        public void onResponse(Call call, Response response) throws IOException {
            try {
                ResponseMyInfo responseMyInfo = (ResponseMyInfo) new Gson().fromJson(response.body().string(), ResponseMyInfo.class);
                if (responseMyInfo.isSuccess()) {
                    PanelSettingsActivity.this.setUIMyInfo(responseMyInfo.getMyInfo());
                    return;
                }
                PanelSettingsActivity.this.showToast((int) R.string.settings_err_my_info);
                PanelSettingsActivity.this.hideLoading();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };
    private ProgressDialog mProgress;
    private TextView mTvUpdate;
    private TextView mTvVersion;
    /* access modifiers changed from: private */
    public String reqStr = "";
    /* access modifiers changed from: private */
    public int req_type = -1;

    /* access modifiers changed from: protected */
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_settings);
        initUI();
        init();
    }

    private void initUI() {
        this.mBodyPush = findViewById(R.id.body_push);
        this.mBodyAgree = findViewById(R.id.body_agree);
        this.mBodyData = findViewById(R.id.body_data);
        this.mTvVersion = (TextView) findViewById(R.id.tv_version);
        this.mTvUpdate = (TextView) findViewById(R.id.tv_update);
        findViewById(R.id.btn_back).setOnClickListener(this.mClick);
        findViewById(R.id.btn_agree_push).setOnClickListener(this.mClick);
        findViewById(R.id.btn_agree_email).setOnClickListener(this.mClick);
        findViewById(R.id.btn_agree_mobile).setOnClickListener(this.mClick);
        findViewById(R.id.btn_agree_call).setOnClickListener(this.mClick);
        findViewById(R.id.btn_location).setOnClickListener(this.mClick);
        findViewById(R.id.btn_app_usage).setOnClickListener(this.mClick);
        findViewById(R.id.btn_pay).setOnClickListener(this.mClick);
        findViewById(R.id.btn_access_term).setOnClickListener(this.mClick);
        findViewById(R.id.btn_privacy_policy).setOnClickListener(this.mClick);
        findViewById(R.id.btn_direction).setOnClickListener(this.mClick);
        findViewById(R.id.btn_version).setOnClickListener(this.mClick);
        setSpannableText(findViewById(R.id.tv_desc_html_location), getString(R.string.settings_msg_location_des2));
        setSpannableText(findViewById(R.id.tv_desc_html_usage), getString(R.string.settings_msg_usage_des2));
        setSpannableText(findViewById(R.id.tv_desc_html_pay), getString(R.string.settings_msg_pay_des2));
    }

    private void setSpannableText(View view, String str) {
        if (!StringUtils.isEmpty(str) && (view instanceof TextView)) {
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(str);
            spannableStringBuilder.setSpan(new ForegroundColorSpan(Color.parseColor("#225ce3")), 6, str.length(), 33);
            ((TextView) view).setText(spannableStringBuilder);
        }
    }

    private void init() {
        login();
        checkAppVersion();
        TextView textView = this.mTvVersion;
        StringBuilder sb = new StringBuilder();
        sb.append("Ver ");
        sb.append(DeviceUtils.getAppVersion(getBaseContext()));
        textView.setText(sb.toString());
    }

    private void login() {
        if (UserInfoManager.getInstance(getApplicationContext()).getUserInfo() != null) {
            showLoading();
            HttpManager.getInstance().requestLogin(LoginVo.getLoginInfo(getBaseContext()), this.mLoginCallback);
        }
    }

    /* access modifiers changed from: private */
    public void showToast(int i) {
        showToast(getString(i));
    }

    private void showToast(final String str) {
        runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(PanelSettingsActivity.this, str, 0).show();
            }
        });
    }

    /* access modifiers changed from: private */
    public void showPopup(int i) {
        showPopup(getString(i));
    }

    private void showPopup(final String str) {
        runOnUiThread(new Runnable() {
            public void run() {
                PanelDialog panelDialog = new PanelDialog((Context) PanelSettingsActivity.this, (String) "\ud655\uc778", str, (String) null, (String) "\ud655\uc778", (IDialogCallBack) null);
                panelDialog.show();
            }
        });
    }

    private void showLoading() {
        try {
            this.mProgress = new ProgressDialog(this);
            this.mProgress.setMessage("\uc0ac\uc6a9\uc790 \uc815\ubcf4\ub97c \ud655\uc778 \uc911\uc785\ub2c8\ub2e4.");
            this.mProgress.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void hideLoading() {
        try {
            this.mProgress.dismiss();
        } catch (Exception unused) {
        }
    }

    /* access modifiers changed from: private */
    public void setUIUserInfo(final UserSession userSession) {
        runOnUiThread(new Runnable() {
            public void run() {
                UserSession userSession = userSession;
                if (userSession == null || StringUtils.isEmpty(userSession.panelId)) {
                    PanelSettingsActivity.this.mBodyPush.setVisibility(8);
                    PanelSettingsActivity.this.mBodyAgree.setVisibility(8);
                    PanelSettingsActivity.this.mBodyData.setVisibility(8);
                    return;
                }
                PanelSettingsActivity.this.mBodyPush.setVisibility(0);
                PanelSettingsActivity.this.mBodyData.setVisibility(0);
                PanelSettingsActivity panelSettingsActivity = PanelSettingsActivity.this;
                panelSettingsActivity.setToggle(DeviceUtils.hasPushPermission(panelSettingsActivity.getBaseContext()), userSession.isPushYnSurvey, PanelSettingsActivity.this.findViewById(R.id.btn_agree_push), PanelSettingsActivity.this.findViewById(R.id.cau_body_push));
                PanelSettingsActivity panelSettingsActivity2 = PanelSettingsActivity.this;
                panelSettingsActivity2.setToggle(DeviceUtils.hasLocationPermission(panelSettingsActivity2.getBaseContext()), userSession.infoLocation, PanelSettingsActivity.this.findViewById(R.id.btn_location), PanelSettingsActivity.this.findViewById(R.id.cau_body_location));
                PanelSettingsActivity panelSettingsActivity3 = PanelSettingsActivity.this;
                panelSettingsActivity3.setToggle(DeviceUtils.hasUsagePermission(panelSettingsActivity3.getBaseContext()), userSession.infoExt, PanelSettingsActivity.this.findViewById(R.id.btn_app_usage), PanelSettingsActivity.this.findViewById(R.id.cau_body_usage));
                PanelSettingsActivity panelSettingsActivity4 = PanelSettingsActivity.this;
                panelSettingsActivity4.setToggle(HabitSignalManager.hasNotificationAccess(panelSettingsActivity4.getBaseContext()), userSession.infoPay, PanelSettingsActivity.this.findViewById(R.id.btn_pay), PanelSettingsActivity.this.findViewById(R.id.cau_body_pay));
                HttpManager.getInstance().requestMyInfo(new MyInfoVo(userSession.panelId), PanelSettingsActivity.this.mMyInfoCallback);
            }
        });
    }

    /* access modifiers changed from: private */
    public void setUIMyInfo(final MyInfo myInfo) {
        runOnUiThread(new Runnable() {
            public void run() {
                MyInfo myInfo = myInfo;
                if (myInfo == null || StringUtils.isEmpty(myInfo.panelId)) {
                    PanelSettingsActivity.this.mBodyAgree.setVisibility(8);
                    return;
                }
                PanelSettingsActivity.this.mBodyAgree.setVisibility(0);
                PanelSettingsActivity.this.setToggle(true, myInfo.emailAgree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_email), PanelSettingsActivity.this.findViewById(R.id.cau_body_email));
                PanelSettingsActivity.this.setToggle(true, myInfo.smsAgree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_mobile), PanelSettingsActivity.this.findViewById(R.id.cau_body_mobile));
                PanelSettingsActivity.this.setToggle(true, myInfo.callAgree, PanelSettingsActivity.this.findViewById(R.id.btn_agree_call), PanelSettingsActivity.this.findViewById(R.id.cau_body_call));
                PanelSettingsActivity.this.hideLoading();
            }
        });
    }

    /* access modifiers changed from: private */
    public void setUIVersion(final AppVersionVO appVersionVO) {
        runOnUiThread(new Runnable() {
            public void run() {
                if (!DeviceUtils.getAppVersion(PanelSettingsActivity.this.getApplicationContext()).equals(appVersionVO.latestVersion)) {
                    PanelSettingsActivity.this.findViewById(R.id.tv_update).setVisibility(0);
                    PanelSettingsActivity.this.findViewById(R.id.btn_version).setOnClickListener(new OnClickListener() {
                        public void onClick(View view) {
                            PanelDialog panelDialog = new PanelDialog((Context) PanelSettingsActivity.this, (String) "\uc5c5\ub370\uc774\ud2b8", PanelSettingsActivity.this.getString(R.string.settings_dialog_new_update), (String) "\ucde8\uc18c", (String) "\uc5c5\ub370\uc774\ud2b8", (IDialogCallBack) new IDialogCallBack() {
                                public void onCallBack(RESULT_CODE result_code) {
                                    if (result_code == RESULT_CODE.RIGHT_CLICK) {
                                        DeviceUtils.goMarket(PanelSettingsActivity.this);
                                    }
                                }
                            });
                            panelDialog.show();
                        }
                    });
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void setToggle(boolean z, String str, View view, View view2) {
        final boolean z2 = z;
        final String str2 = str;
        final View view3 = view;
        final View view4 = view2;
        AnonymousClass6 r0 = new Runnable() {
            public void run() {
                if (!z2 || !UserInfoManager.AGREE_Y.equals(str2)) {
                    view3.setBackgroundResource(R.drawable.toggle_off);
                    view4.setVisibility(0);
                    view3.setTag("N");
                    return;
                }
                view3.setBackgroundResource(R.drawable.toggle_on);
                view4.setVisibility(8);
                view3.setTag(UserInfoManager.AGREE_Y);
            }
        };
        runOnUiThread(r0);
    }

    /* access modifiers changed from: private */
    public void callPopupBrowser(String str) {
        Intent intent = new Intent(this, PopupBrowserActivity.class);
        intent.putExtra(PopupBrowserActivity.EXTRA_URL, str);
        startActivity(intent);
    }

    /* access modifiers changed from: private */
    public void agree(int i) {
        String string;
        String panelId = UserInfoManager.getInstance(getBaseContext()).getPanelId();
        this.agree = (String) findViewById(i).getTag();
        this.agree = "N".equals(this.agree) ? UserInfoManager.AGREE_Y : "N";
        switch (i) {
            case R.id.btn_agree_call /*2131296340*/:
                this.req_type = 4;
                this.reqStr = new AgreeCallVo(panelId, this.agree).toJson();
                string = getString(R.string.settings_dialog_call_off);
                break;
            case R.id.btn_agree_email /*2131296341*/:
                this.req_type = 2;
                this.reqStr = new AgreeEmailVo(panelId, this.agree).toJson();
                string = getString(R.string.settings_dialog_email_off);
                break;
            case R.id.btn_agree_mobile /*2131296342*/:
                this.req_type = 3;
                this.reqStr = new AgreeMobileVo(panelId, this.agree).toJson();
                string = getString(R.string.settings_dialog_mobile_off);
                break;
            case R.id.btn_agree_push /*2131296343*/:
                this.req_type = 1;
                this.reqStr = new AgreePushVo(panelId, this.agree).toJson();
                string = getString(R.string.settings_dialog_push_off);
                break;
            case R.id.btn_app_usage /*2131296344*/:
                this.req_type = 6;
                this.reqStr = new AgreeUsageVo(panelId, this.agree).toJson();
                string = getString(R.string.settings_dialog_usage_off);
                break;
            default:
                switch (i) {
                    case R.id.btn_location /*2131296351*/:
                        this.req_type = 5;
                        this.reqStr = new AgreeLocationVo(panelId, this.agree).toJson();
                        string = getString(R.string.settings_dialog_location_off);
                        break;
                    case R.id.btn_pay /*2131296352*/:
                        this.req_type = 7;
                        this.reqStr = new AgreePayVo(panelId, this.agree).toJson();
                        string = getString(R.string.settings_dialog_pay_off);
                        break;
                    default:
                        string = "";
                        break;
                }
        }
        String str = string;
        if ("N".equals(this.agree)) {
            PanelDialog panelDialog = new PanelDialog((Context) this, (String) "\ud655\uc778", str, (String) "\ucde8\uc18c", (String) "\ud655\uc778", (IDialogCallBack) new IDialogCallBack() {
                public void onCallBack(RESULT_CODE result_code) {
                    if (result_code == RESULT_CODE.RIGHT_CLICK) {
                        HttpManager.getInstance().requestAgree(PanelSettingsActivity.this.req_type, PanelSettingsActivity.this.reqStr, PanelSettingsActivity.this.mAgreeCallback);
                    }
                }
            });
            panelDialog.show();
        } else if (hasDevicePermission(i)) {
            HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
        }
    }

    private boolean hasDevicePermission(int i) {
        switch (i) {
            case R.id.btn_agree_push /*2131296343*/:
                if (!DeviceUtils.hasPushPermission(getBaseContext())) {
                    DeviceUtils.setPushPermission(this);
                    return false;
                }
                break;
            case R.id.btn_app_usage /*2131296344*/:
                if (!DeviceUtils.hasUsagePermission(getBaseContext())) {
                    DeviceUtils.setUsagePermission(this);
                    return false;
                }
                break;
            case R.id.btn_location /*2131296351*/:
                if (!DeviceUtils.hasLocationPermission(getBaseContext())) {
                    DeviceUtils.setLocationPermission(this);
                    return false;
                }
                break;
            case R.id.btn_pay /*2131296352*/:
                if (!HabitSignalManager.hasNotificationAccess(getBaseContext())) {
                    HabitSignalManager.setPayPermission(this);
                    return false;
                }
                break;
        }
        return true;
    }

    public void onRequestPermissionsResult(int i, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i, strArr, iArr);
        String panelId = UserInfoManager.getInstance(getBaseContext()).getPanelId();
        if (i == 1002) {
            for (int i2 = 0; i2 < strArr.length; i2++) {
                if (iArr[i2] == -1) {
                    this.agree = "N";
                    this.reqStr = new AgreeLocationVo(panelId, "N").toJson();
                    HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
                    return;
                }
            }
            this.agree = UserInfoManager.AGREE_Y;
            this.reqStr = new AgreeLocationVo(panelId, UserInfoManager.AGREE_Y).toJson();
            HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int i, int i2, @Nullable Intent intent) {
        super.onActivityResult(i, i2, intent);
        String panelId = UserInfoManager.getInstance(getBaseContext()).getPanelId();
        if (i == 1008) {
            if (HabitSignalManager.hasNotificationAccess(this)) {
                this.agree = UserInfoManager.AGREE_Y;
                this.reqStr = new AgreePayVo(panelId, UserInfoManager.AGREE_Y).toJson();
                HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
                return;
            }
            this.agree = "N";
            this.reqStr = new AgreePayVo(panelId, "N").toJson();
            HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
        } else if (i == 1009) {
            if (DeviceUtils.hasUsagePermission(this)) {
                this.agree = UserInfoManager.AGREE_Y;
                this.reqStr = new AgreeUsageVo(panelId, UserInfoManager.AGREE_Y).toJson();
                HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
                return;
            }
            this.agree = "N";
            this.reqStr = new AgreeUsageVo(panelId, "N").toJson();
            HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
        } else if (i != 1010) {
        } else {
            if (DeviceUtils.hasPushPermission(this)) {
                this.agree = UserInfoManager.AGREE_Y;
                this.reqStr = new AgreePushVo(panelId, UserInfoManager.AGREE_Y).toJson();
                HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
                return;
            }
            this.agree = "N";
            this.reqStr = new AgreePushVo(panelId, "N").toJson();
            HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
        }
    }

    public void finishActivity(int i) {
        super.finishActivity(i);
    }

    public void checkAppVersion() {
        AppVersionVO appVersionVO = new AppVersionVO();
        appVersionVO.osTpCd = "A";
        appVersionVO.version = DeviceUtils.getAppVersion(this);
        HttpManager.getInstance().requestVersionCheck(appVersionVO, new Callback() {
            public void onFailure(Call call, IOException iOException) {
                PanelSettingsActivity.this.showToast((int) R.string.common_app_network_fail);
            }

            public void onResponse(Call call, Response response) throws IOException {
                try {
                    if (response.code() == 200) {
                        ResponseCheckAppVersion responseCheckAppVersion = (ResponseCheckAppVersion) new Gson().fromJson(response.body().string(), ResponseCheckAppVersion.class);
                        if (!responseCheckAppVersion.isSuccess()) {
                            PanelSettingsActivity.this.showToast((int) R.string.common_app_version_check_fail);
                        } else if (responseCheckAppVersion.appVersion == null) {
                            PanelSettingsActivity.this.showToast((int) R.string.common_app_version_check_fail);
                        } else {
                            PanelSettingsActivity.this.setUIVersion(responseCheckAppVersion.appVersion);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    PanelSettingsActivity.this.showToast((int) R.string.common_app_version_check_fail);
                }
            }
        });
    }
}