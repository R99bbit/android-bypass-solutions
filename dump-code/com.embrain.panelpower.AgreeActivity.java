package com.embrain.panelpower;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.webkit.WebSettings;
import android.webkit.WebSettings.LayoutAlgorithm;
import android.webkit.WebView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.embrain.panelbigdata.utils.DeviceUtils;
import com.embrain.panelpower.UserInfoManager.UserInfo;
import com.embrain.panelpower.habit_signal.HabitSignalManager;
import com.embrain.panelpower.hybrid.AgreeWebViewJavascript;
import com.embrain.panelpower.hybrid.IntroWebviewJavaScript;
import com.embrain.panelpower.networks.HttpManager;
import com.embrain.panelpower.networks.vo.AgreeLocationVo;
import com.embrain.panelpower.networks.vo.AgreePayVo;
import com.embrain.panelpower.networks.vo.AgreePushVo;
import com.embrain.panelpower.networks.vo.AgreeUsageVo;
import com.embrain.panelpower.networks.vo.PanelBasicResponse;
import com.embrain.panelpower.views.PanelDialog;
import com.embrain.panelpower.views.PanelDialog.IDialogCallBack;
import com.embrain.panelpower.vo.DeviceInfo;
import com.google.gson.Gson;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.PriorityQueue;
import java.util.Queue;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class AgreeActivity extends AppCompatActivity {
    public static final int AGREE_TYPE_LOCATION = 3;
    public static final int AGREE_TYPE_PAY = 1;
    public static final int AGREE_TYPE_PUSH = 4;
    public static final int AGREE_TYPE_USAGE = 2;
    private static final int CONFIRM_LOCATION_AGREE = 40;
    private static final int CONFIRM_LOCATION_DENIED = 41;
    private static final int CONFIRM_PAY_AGREE = 32;
    private static final int CONFIRM_PAY_DENIED = 33;
    private static final int CONFIRM_PUSH_AGREE = 50;
    private static final int CONFIRM_PUSH_DENIED = 51;
    private static final int CONFIRM_USAGE_AGREE = 30;
    private static final int CONFIRM_USAGE_DENIED = 31;
    public static final String EXTRA_AGREE_TYPE = "agree_type";
    public static final String EXTRA_FROM_FLOATING = "from_floating";
    private static final String HTML_AGREE_LOCATION = "access_agree2.html";
    private static final String HTML_AGREE_PUSH = "access_agree3.html";
    private static final String HTML_PAY = "access_agree4.html";
    private static final String HTML_USAGE = "access_agree1.html";
    private static final String LOCATION = "file:///android_asset/html/intro/";
    public static final int REQUEST_CODE_AGREE_ACTIVITY = 8099;
    private static final int SHOW_TOAST = 80;
    private static final String TYPE_DETAIL_PAY = "pay";
    private static final String TYPE_DETAIL_USAGE = "usage";
    /* access modifiers changed from: private */
    public Queue<PROCESS> SEQUENCE;
    /* access modifiers changed from: private */
    public boolean fromFloating = false;
    /* access modifiers changed from: private */
    public boolean isNetworking = false;
    private Callback mAgreeCallback = new Callback() {
        public void onResponse(Call call, Response response) throws IOException {
            try {
                if (((PanelBasicResponse) new Gson().fromJson(response.body().string(), PanelBasicResponse.class)).isSuccess()) {
                    int access$500 = AgreeActivity.this.req_type;
                    if (access$500 != 1) {
                        if (access$500 != 5) {
                            if (access$500 != 6) {
                                if (access$500 == 7) {
                                    if (UserInfoManager.AGREE_Y.equals(AgreeActivity.this.reqAgree)) {
                                        UserInfoManager.setAgreePay(AgreeActivity.this.getApplicationContext(), UserInfoManager.AGREE_Y);
                                    } else {
                                        UserInfoManager.setAgreePay(AgreeActivity.this.getApplicationContext(), "N");
                                        if (AgreeActivity.this.fromFloating) {
                                            UserInfoManager.addFloatDeniedCntPay(AgreeActivity.this.getApplicationContext());
                                        } else {
                                            UserInfoManager.addDeniedCntPay(AgreeActivity.this.getApplicationContext());
                                        }
                                    }
                                }
                            } else if (UserInfoManager.AGREE_Y.equals(AgreeActivity.this.reqAgree)) {
                                UserInfoManager.setAgreeUsage(AgreeActivity.this.getApplicationContext(), UserInfoManager.AGREE_Y);
                            } else {
                                UserInfoManager.setAgreeUsage(AgreeActivity.this.getApplicationContext(), "N");
                                if (AgreeActivity.this.fromFloating) {
                                    UserInfoManager.addFloatDeniedCntUsage(AgreeActivity.this.getApplicationContext());
                                } else {
                                    UserInfoManager.addDeniedCntUsage(AgreeActivity.this.getApplicationContext());
                                }
                            }
                        } else if (UserInfoManager.AGREE_Y.equals(AgreeActivity.this.reqAgree)) {
                            UserInfoManager.setAgreeLocation(AgreeActivity.this.getApplicationContext(), UserInfoManager.AGREE_Y);
                        } else {
                            UserInfoManager.setAgreeLocation(AgreeActivity.this.getApplicationContext(), "N");
                            if (AgreeActivity.this.fromFloating) {
                                UserInfoManager.addFloatDeniedCntLocation(AgreeActivity.this.getApplicationContext());
                            } else {
                                UserInfoManager.addDeniedCntLocation(AgreeActivity.this.getApplicationContext());
                            }
                        }
                    } else if (UserInfoManager.AGREE_Y.equals(AgreeActivity.this.reqAgree)) {
                        UserInfoManager.setAgreePush(AgreeActivity.this.getApplicationContext(), UserInfoManager.AGREE_Y);
                    } else {
                        UserInfoManager.setAgreePush(AgreeActivity.this.getApplicationContext(), "N");
                        if (AgreeActivity.this.fromFloating) {
                            UserInfoManager.addFloatDeniedCntPush(AgreeActivity.this.getApplicationContext());
                        } else {
                            UserInfoManager.addDeniedCntPush(AgreeActivity.this.getApplicationContext());
                        }
                    }
                } else {
                    AgreeActivity.this.showPopup((int) R.string.settings_dialog_agree_failed);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Throwable th) {
                AgreeActivity.this.req_type = -1;
                AgreeActivity.this.reqStr = "";
                AgreeActivity.this.reqAgree = "";
                AgreeActivity.this.isNetworking = false;
                AgreeActivity.this.process();
                throw th;
            }
            AgreeActivity.this.req_type = -1;
            AgreeActivity.this.reqStr = "";
            AgreeActivity.this.reqAgree = "";
            AgreeActivity.this.isNetworking = false;
            AgreeActivity.this.process();
        }

        public void onFailure(Call call, IOException iOException) {
            AgreeActivity.this.showPopup((int) R.string.settings_dialog_agree_failed);
            AgreeActivity.this.req_type = -1;
            AgreeActivity.this.reqStr = "";
            AgreeActivity.this.reqAgree = "";
            AgreeActivity.this.isNetworking = false;
            AgreeActivity.this.process();
        }
    };
    /* access modifiers changed from: private */
    public final ResultHandler mHandler = new ResultHandler(this);
    private AgreeWebViewJavascript mInterface = new AgreeWebViewJavascript() {
        public void onPayAgree(boolean z) {
            if (z) {
                AgreeActivity.this.mHandler.sendEmptyMessage(32);
            } else {
                AgreeActivity.this.mHandler.sendEmptyMessage(33);
            }
        }

        public void onUsageAgree(boolean z) {
            if (z) {
                AgreeActivity.this.mHandler.sendEmptyMessage(30);
            } else {
                AgreeActivity.this.mHandler.sendEmptyMessage(31);
            }
        }

        public void onLocationAgree(boolean z) {
            if (z) {
                AgreeActivity.this.mHandler.sendEmptyMessage(40);
            } else {
                AgreeActivity.this.mHandler.sendEmptyMessage(41);
            }
        }

        public void onPushAgree(boolean z) {
            if (z) {
                AgreeActivity.this.mHandler.sendEmptyMessage(50);
            } else {
                AgreeActivity.this.mHandler.sendEmptyMessage(51);
            }
        }

        public void showDetail(String str) {
            Intent intent = new Intent(AgreeActivity.this, PopupBrowserActivity.class);
            if ("usage".equals(str)) {
                intent.putExtra(PopupBrowserActivity.EXTRA_URL, PanelApplication.URL_INFO_USAGE);
            } else if (AgreeActivity.TYPE_DETAIL_PAY.equals(str)) {
                intent.putExtra(PopupBrowserActivity.EXTRA_URL, PanelApplication.URL_INFO_PAY);
            }
            AgreeActivity.this.startActivity(intent);
        }

        public String onRequestDeviceInfo() {
            return new DeviceInfo(AgreeActivity.this.getApplicationContext()).toJson();
        }
    };
    private UserInfo mUserInfo;
    private WebView mWebView;
    /* access modifiers changed from: private */
    public String reqAgree = "";
    /* access modifiers changed from: private */
    public String reqStr = "";
    /* access modifiers changed from: private */
    public int req_type = -1;

    /* renamed from: com.embrain.panelpower.AgreeActivity$5 reason: invalid class name */
    static /* synthetic */ class AnonymousClass5 {
        static final /* synthetic */ int[] $SwitchMap$com$embrain$panelpower$AgreeActivity$PROCESS = new int[PROCESS.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(10:0|1|2|3|4|5|6|7|8|10) */
        /* JADX WARNING: Can't wrap try/catch for region: R(8:0|1|2|3|4|5|6|(3:7|8|10)) */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        /* JADX WARNING: Missing exception handler attribute for start block: B:5:0x001f */
        /* JADX WARNING: Missing exception handler attribute for start block: B:7:0x002a */
        static {
            $SwitchMap$com$embrain$panelpower$AgreeActivity$PROCESS[PROCESS.PAY.ordinal()] = 1;
            $SwitchMap$com$embrain$panelpower$AgreeActivity$PROCESS[PROCESS.USAGE.ordinal()] = 2;
            $SwitchMap$com$embrain$panelpower$AgreeActivity$PROCESS[PROCESS.LOCATION.ordinal()] = 3;
            try {
                $SwitchMap$com$embrain$panelpower$AgreeActivity$PROCESS[PROCESS.PUSH.ordinal()] = 4;
            } catch (NoSuchFieldError unused) {
            }
        }
    }

    private enum PROCESS {
        PAY,
        USAGE,
        LOCATION,
        PUSH
    }

    static class ResultHandler extends Handler {
        private final WeakReference<AgreeActivity> mActivity;

        ResultHandler(AgreeActivity agreeActivity) {
            this.mActivity = new WeakReference<>(agreeActivity);
        }

        public void handleMessage(Message message) {
            AgreeActivity agreeActivity = (AgreeActivity) this.mActivity.get();
            if (agreeActivity != null) {
                agreeActivity.handleMessage(message);
            }
        }
    }

    public void onBackPressed() {
    }

    /* access modifiers changed from: protected */
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_agree);
        this.mWebView = (WebView) findViewById(R.id.webview_agree);
        WebSettings settings = this.mWebView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setSupportMultipleWindows(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setSupportZoom(true);
        settings.setBuiltInZoomControls(true);
        settings.setDisplayZoomControls(false);
        settings.setLayoutAlgorithm(LayoutAlgorithm.NORMAL);
        settings.setCacheMode(2);
        settings.setDomStorageEnabled(true);
        this.mWebView.addJavascriptInterface(this.mInterface, IntroWebviewJavaScript.getName());
        init();
    }

    private void init() {
        this.mUserInfo = UserInfoManager.getInstance(getBaseContext()).getUserInfo();
        if (this.mUserInfo == null) {
            finish();
            return;
        }
        int intExtra = getIntent().getIntExtra(EXTRA_AGREE_TYPE, -1);
        this.fromFloating = getIntent().getBooleanExtra(EXTRA_FROM_FLOATING, false);
        this.SEQUENCE = new PriorityQueue();
        if (intExtra == 1) {
            this.SEQUENCE.offer(PROCESS.PAY);
        } else if (intExtra == 2) {
            this.SEQUENCE.offer(PROCESS.USAGE);
        } else if (intExtra == 3) {
            this.SEQUENCE.offer(PROCESS.LOCATION);
        } else if (intExtra != 4) {
            setProcess();
        } else {
            this.SEQUENCE.offer(PROCESS.PUSH);
        }
        process();
    }

    private void setProcess() {
        if (showPay(getBaseContext())) {
            this.SEQUENCE.offer(PROCESS.PAY);
        } else if (showUsage(getBaseContext())) {
            this.SEQUENCE.offer(PROCESS.USAGE);
        }
        if (showLocation(getBaseContext())) {
            this.SEQUENCE.offer(PROCESS.LOCATION);
        }
        if (showPush(getBaseContext())) {
            this.SEQUENCE.offer(PROCESS.PUSH);
        }
    }

    /* access modifiers changed from: private */
    public void finishAgree() {
        setResult(-1);
        finish();
    }

    /* access modifiers changed from: private */
    public void process() {
        runOnUiThread(new Runnable() {
            public void run() {
                PROCESS process = (PROCESS) AgreeActivity.this.SEQUENCE.poll();
                if (process == null) {
                    AgreeActivity.this.finishAgree();
                    return;
                }
                int i = AnonymousClass5.$SwitchMap$com$embrain$panelpower$AgreeActivity$PROCESS[process.ordinal()];
                if (i == 1) {
                    AgreeActivity.this.loadHtml(AgreeActivity.HTML_PAY);
                } else if (i == 2) {
                    AgreeActivity.this.loadHtml(AgreeActivity.HTML_USAGE);
                } else if (i == 3) {
                    AgreeActivity.this.loadHtml(AgreeActivity.HTML_AGREE_LOCATION);
                } else if (i == 4) {
                    AgreeActivity.this.loadHtml(AgreeActivity.HTML_AGREE_PUSH);
                }
            }
        });
    }

    public static boolean showAgree(Context context) {
        boolean z = false;
        try {
            if (UserInfoManager.getInstance(context).getUserInfo() == null) {
                return false;
            }
            String memSection = UserInfoManager.getInstance(context).getUserInfo().getMemSection();
            if (!"M".equals(memSection) && !"P".equals(memSection) && !"E".equals(memSection)) {
                return false;
            }
            if (showPay(context) || showUsage(context) || showLocation(context) || showPush(context)) {
                z = true;
            }
            return z;
        } catch (Exception unused) {
        }
    }

    public static boolean showPay(Context context) {
        return showPay(context, true);
    }

    public static boolean showPay(Context context, boolean z) {
        boolean z2 = false;
        if (UserInfoManager.getInstance(context).getUserInfo() == null) {
            return false;
        }
        boolean z3 = !HabitSignalManager.hasNotificationAccess(context);
        boolean z4 = !UserInfoManager.AGREE_Y.equals(UserInfoManager.getInstance(context).getUserInfo().infoPay);
        boolean z5 = UserInfoManager.getDeniedCntPay(context) < 2;
        if ((z3 || z4) && (!z || z5)) {
            z2 = true;
        }
        return z2;
    }

    public static boolean showUsage(Context context) {
        return showUsage(context, true);
    }

    public static boolean showUsage(Context context, boolean z) {
        boolean z2 = false;
        if (UserInfoManager.getInstance(context).getUserInfo() == null) {
            return false;
        }
        boolean z3 = !DeviceUtils.hasUsagePermission(context);
        boolean z4 = !UserInfoManager.AGREE_Y.equals(UserInfoManager.getInstance(context).getUserInfo().infoExt);
        boolean z5 = UserInfoManager.getDeniedCntUsage(context) < 2;
        if ((z3 || z4) && (!z || z5)) {
            z2 = true;
        }
        return z2;
    }

    public static boolean showLocation(Context context) {
        return showLocation(context, true);
    }

    public static boolean showLocation(Context context, boolean z) {
        boolean z2 = false;
        if (UserInfoManager.getInstance(context).getUserInfo() == null) {
            return false;
        }
        boolean z3 = !DeviceUtils.hasLocationPermission(context);
        boolean z4 = !UserInfoManager.AGREE_Y.equals(UserInfoManager.getInstance(context).getUserInfo().infoLocation);
        boolean z5 = UserInfoManager.getDeniedCntLocation(context) < 1;
        if ((z3 || z4) && (!z || z5)) {
            z2 = true;
        }
        return z2;
    }

    public static boolean showPush(Context context) {
        boolean z = false;
        if (UserInfoManager.getInstance(context).getUserInfo() == null) {
            return false;
        }
        boolean z2 = !DeviceUtils.hasPushPermission(context);
        boolean z3 = !UserInfoManager.AGREE_Y.equals(UserInfoManager.getInstance(context).getUserInfo().isPushYnSurvey);
        boolean z4 = UserInfoManager.getDeniedCntPush(context) < 1;
        if ((z2 || z3) && z4) {
            z = true;
        }
        return z;
    }

    /* access modifiers changed from: private */
    public void loadHtml(String str) {
        WebView webView = this.mWebView;
        StringBuilder sb = new StringBuilder();
        sb.append(LOCATION);
        sb.append(str);
        webView.loadUrl(sb.toString());
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int i, int i2, @Nullable Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 1008) {
            if (HabitSignalManager.hasNotificationAccess(this)) {
                agree(7, UserInfoManager.AGREE_Y);
            } else {
                process();
            }
        } else if (i == 1009) {
            if (DeviceUtils.hasUsagePermission(this)) {
                agree(6, UserInfoManager.AGREE_Y);
            } else {
                process();
            }
        } else if (i != 1010) {
        } else {
            if (DeviceUtils.hasPushPermission(this)) {
                agree(1, UserInfoManager.AGREE_Y);
            } else {
                process();
            }
        }
    }

    public void onRequestPermissionsResult(int i, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i, strArr, iArr);
        if (i == 1002) {
            for (int i2 : iArr) {
                if (i2 == -1) {
                    process();
                    return;
                }
            }
            agree(5, UserInfoManager.AGREE_Y);
            process();
        }
    }

    /* access modifiers changed from: private */
    public void handleMessage(Message message) {
        int i = message.what;
        if (i != 40) {
            if (i == 41) {
                agree(5, "N");
            } else if (i != 50) {
                if (i == 51) {
                    agree(1, "N");
                } else if (i != 80) {
                    switch (i) {
                        case 30:
                            if (DeviceUtils.hasUsagePermission(getBaseContext())) {
                                agree(6, UserInfoManager.AGREE_Y);
                                return;
                            } else {
                                DeviceUtils.setUsagePermission(this);
                                return;
                            }
                        case 31:
                            agree(6, "N");
                            return;
                        case 32:
                            if (HabitSignalManager.hasNotificationAccess(getBaseContext())) {
                                agree(7, UserInfoManager.AGREE_Y);
                                return;
                            } else {
                                HabitSignalManager.setPayPermission(this);
                                return;
                            }
                        case 33:
                            agree(7, "N");
                            return;
                        default:
                            return;
                    }
                } else {
                    Toast.makeText(getApplicationContext(), (String) message.obj, 0).show();
                }
            } else if (DeviceUtils.hasPushPermission(getApplicationContext())) {
                agree(1, UserInfoManager.AGREE_Y);
            } else {
                DeviceUtils.setPushPermission(this);
            }
        } else if (DeviceUtils.hasLocationPermission(getApplicationContext())) {
            agree(5, UserInfoManager.AGREE_Y);
        } else {
            DeviceUtils.setLocationPermission(this);
        }
    }

    /* access modifiers changed from: private */
    public void showPopup(int i) {
        showPopup(getString(i));
    }

    private void showPopup(final String str) {
        runOnUiThread(new Runnable() {
            public void run() {
                PanelDialog panelDialog = new PanelDialog((Context) AgreeActivity.this, (String) "\ud655\uc778", str, (String) null, (String) "\ud655\uc778", (IDialogCallBack) null);
                panelDialog.show();
            }
        });
    }

    private synchronized void agree(int i, String str) {
        try {
            if (this.isNetworking) {
                Toast.makeText(getApplicationContext(), R.string.common_network_processing, 0).show();
                return;
            }
            this.req_type = i;
            this.reqAgree = str;
            String panelId = UserInfoManager.getInstance(getBaseContext()).getPanelId();
            int i2 = this.req_type;
            if (i2 == 1) {
                this.reqStr = new AgreePushVo(panelId, str).toJson();
            } else if (i2 == 5) {
                this.reqStr = new AgreeLocationVo(panelId, str).toJson();
            } else if (i2 == 6) {
                this.reqStr = new AgreeUsageVo(panelId, str).toJson();
            } else if (i2 == 7) {
                this.reqStr = new AgreePayVo(panelId, str).toJson();
            }
            this.isNetworking = true;
            HttpManager.getInstance().requestAgree(this.req_type, this.reqStr, this.mAgreeCallback);
        } catch (Exception e) {
            e.printStackTrace();
            process();
        }
    }
}