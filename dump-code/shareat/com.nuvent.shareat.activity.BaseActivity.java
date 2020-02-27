package com.nuvent.shareat.activity;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningTaskInfo;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.v4.app.FragmentActivity;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.TextView;
import android.widget.Toast;
import com.crashlytics.android.Crashlytics;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.LoginEvent;
import com.gun0912.tedpermission.PermissionListener;
import com.gun0912.tedpermission.TedPermission;
import com.gun0912.tedpermission.TedPermission.Builder;
import com.igaworks.adbrix.IgawAdbrix;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.common.ConfirmPasswordActivity;
import com.nuvent.shareat.activity.intro.SigninActivity;
import com.nuvent.shareat.activity.intro.SignupActivity;
import com.nuvent.shareat.activity.main.ActionGuideActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.SocketInfoApi;
import com.nuvent.shareat.api.intro.SignedCheckApi;
import com.nuvent.shareat.dialog.LoadingCircleDialog;
import com.nuvent.shareat.dialog.LoadingDialog;
import com.nuvent.shareat.exception.NetworkException;
import com.nuvent.shareat.manager.GpsManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.manager.socket.SocketInterface;
import com.nuvent.shareat.model.SignedModel;
import com.nuvent.shareat.model.SocketResultModel;
import com.nuvent.shareat.model.user.CardResultModel;
import com.nuvent.shareat.model.user.UserModel;
import com.nuvent.shareat.util.GAEvent;
import java.net.UnknownHostException;
import java.util.List;
import javax.net.ssl.SSLHandshakeException;
import org.jboss.netty.channel.ConnectTimeoutException;

public class BaseActivity extends FragmentActivity {
    public static final int REQUEST_TYPE_BASEACTIVITY_PASSWORD_CHECK = 1;
    private AlertDialog mAlertDialog = null;
    private LoadingCircleDialog mCircleDialog;
    private GpsManager mGpsManager;
    private LoadingDialog mLoadingDialog;
    /* access modifiers changed from: private */
    public SocketInterface mSocketManager;
    private Toast mToast = null;
    PermissionListener permissionlistener = new PermissionListener() {
        public void onPermissionGranted() {
            BaseActivity.this.requestSignedCheckApi();
        }

        public void onPermissionDenied(List<String> list) {
        }
    };

    public void onStartMainActivity(Intent intent) {
        intent.setFlags(603979776);
        animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
        finish(false);
    }

    public void onStartMainActivity() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.setFlags(67108864);
        animActivity(intent, R.anim.fade_in_activity, R.anim.fade_out_activity);
        finish(false);
    }

    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }

    public void modalActivity(Intent intent) {
        startActivity(intent);
        overridePendingTransition(R.anim.modal_animation, R.anim.scale_down);
    }

    public void pushActivity(Intent intent) {
        startActivity(intent);
        overridePendingTransition(R.anim.slide_from_right, R.anim.slide_out_to_left);
    }

    public void animActivity(Intent intent, int enterAnim, int exitAnim) {
        startActivity(intent);
        overridePendingTransition(enterAnim, exitAnim);
    }

    public void animActivityForResult(Intent intent, int requestCode, int enterAnim, int exitAnim) {
        startActivityForResult(intent, requestCode);
        overridePendingTransition(enterAnim, exitAnim);
    }

    public void finish() {
        super.finish();
        overridePendingTransition(R.anim.slide_from_left, R.anim.slide_out_to_right);
    }

    public void finish(boolean isAnimate) {
        super.finish();
        if (isAnimate) {
            overridePendingTransition(R.anim.slide_from_left, R.anim.slide_out_to_right);
        }
    }

    public void finish(int enterAnim, int exitAnim) {
        super.finish();
        overridePendingTransition(enterAnim, exitAnim);
    }

    public int getStatusBarHeight() {
        int resourceId = getResources().getIdentifier("status_bar_height", "dimen", "android");
        if (resourceId > 0) {
            return getResources().getDimensionPixelSize(resourceId);
        }
        return 0;
    }

    public void showLoadingDialog(boolean visibility) {
        if (this.mLoadingDialog != null && !isFinishing()) {
            if (visibility && !this.mLoadingDialog.isShowing()) {
                this.mLoadingDialog.show();
            }
            if (!visibility && this.mLoadingDialog != null && this.mLoadingDialog.isShowing()) {
                this.mLoadingDialog.dismiss();
            }
        }
    }

    public void showCircleDialog(boolean visibility) {
        if (this.mCircleDialog != null && !isFinishing()) {
            if (visibility && !this.mCircleDialog.isShowing()) {
                this.mCircleDialog.show();
            }
            if (!visibility && this.mCircleDialog != null && this.mCircleDialog.isShowing()) {
                this.mCircleDialog.dismiss();
            }
        }
    }

    public void showToast(String message) {
        if (this.mToast != null) {
            this.mToast.setText(message);
            this.mToast.show();
        }
    }

    public void showLoginDialog() {
        if (!SessionManager.getInstance().hasSession()) {
            ((Builder) ((Builder) TedPermission.with(this).setPermissionListener(this.permissionlistener)).setPermissions("android.permission.READ_PHONE_STATE")).check();
        }
    }

    public void closeDialog() {
        if (this.mAlertDialog != null && true == this.mAlertDialog.isShowing()) {
            this.mAlertDialog.dismiss();
        }
    }

    public void showDialog(String message) {
        showDialog(message, null);
    }

    public void showDialog(String message, OnClickListener onClickListener) {
        try {
            AlertDialog.Builder adBuilder = new AlertDialog.Builder(this);
            adBuilder.setTitle("\uc54c\ub9bc");
            adBuilder.setMessage(message);
            adBuilder.setPositiveButton("\ud655\uc778", onClickListener);
            adBuilder.setCancelable(false);
            adBuilder.create();
            this.mAlertDialog = adBuilder.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showConfirmDialog(String message, String doneText, final Runnable doneRun) {
        try {
            new AlertDialog.Builder(this).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton(doneText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    doneRun.run();
                }
            }).setNegativeButton("\ucde8\uc18c", null).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showConfirmDialog(String message, final Runnable doneRun) {
        try {
            new AlertDialog.Builder(this).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton("\ud655\uc778", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    doneRun.run();
                }
            }).setNegativeButton("\ucde8\uc18c", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (!AppSettingManager.getInstance().getMainListActionGuideStatus()) {
                        BaseActivity.this.animActivity(new Intent(BaseActivity.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "main"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                    }
                }
            }).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showAgreeDialog(String message, final Runnable doneRun) {
        try {
            new AlertDialog.Builder(this).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton("\ub3d9\uc758", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    doneRun.run();
                }
            }).setNegativeButton("\ucde8\uc18c", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (!AppSettingManager.getInstance().getMainListActionGuideStatus()) {
                        BaseActivity.this.animActivity(new Intent(BaseActivity.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "main"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                    }
                }
            }).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showConfirmDialog(String message, final Runnable doneRun, final Activity act) {
        try {
            new AlertDialog.Builder(this).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton("\ud655\uc778", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    GAEvent.onGaEvent(act, (int) R.string.ga_enable_gps_name, (int) R.string.ga_enable_gps_name, (int) R.string.ga_ev_ok);
                    doneRun.run();
                }
            }).setNegativeButton("\ucde8\uc18c", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    GAEvent.onGaEvent(act, (int) R.string.ga_enable_gps_name, (int) R.string.ga_enable_gps_name, (int) R.string.ga_ev_cancle);
                    if (!AppSettingManager.getInstance().getMainListActionGuideStatus()) {
                        BaseActivity.this.animActivity(new Intent(BaseActivity.this.getBaseContext(), ActionGuideActivity.class).putExtra(KakaoTalkLinkProtocol.ACTION_TYPE, "main"), R.anim.fade_in_activity, R.anim.fade_out_activity);
                    }
                }
            }).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showConfirmDialog(String message, final Runnable doneRun, final Runnable cancelRun) {
        try {
            new AlertDialog.Builder(this).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton("\ud655\uc778", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    doneRun.run();
                }
            }).setNegativeButton("\ucde8\uc18c", new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    cancelRun.run();
                }
            }).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showConfirmDialog(String message, String positiveBtnText, String negativeBtnText, final Runnable positiveRunnable, final Runnable negativeRunnable) {
        try {
            new AlertDialog.Builder(this).setTitle("\uc54c\ub9bc").setMessage(message).setPositiveButton(positiveBtnText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (positiveRunnable != null) {
                        positiveRunnable.run();
                    }
                }
            }).setNegativeButton(negativeBtnText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (negativeRunnable != null) {
                        negativeRunnable.run();
                    }
                }
            }).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showConfirmDialog(String title, String message, String positiveBtnText, String negativeBtnText, final Runnable positiveRunnable, final Runnable negativeRunnable) {
        try {
            new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton(positiveBtnText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (positiveRunnable != null) {
                        positiveRunnable.run();
                    }
                }
            }).setNegativeButton(negativeBtnText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (negativeRunnable != null) {
                        negativeRunnable.run();
                    }
                }
            }).setCancelable(false).create().show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showCustomConfirmDialog(String title, String message, String positiveBtnText, String negativeBtnText, Runnable positiveRunnable, Runnable negativeRunnable) {
        try {
            TextView customTitle = new TextView(getApplicationContext());
            customTitle.setText(title);
            customTitle.setTextColor(Color.parseColor("#000000"));
            customTitle.setTextSize(2, 20.0f);
            customTitle.setPadding(70, 50, 0, 0);
            final Runnable runnable = negativeRunnable;
            final Runnable runnable2 = positiveRunnable;
            AlertDialog dialog = new AlertDialog.Builder(this).setCustomTitle(customTitle).setMessage(message).setPositiveButton(negativeBtnText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (runnable != null) {
                        runnable.run();
                    }
                }
            }).setNegativeButton(positiveBtnText, new OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    if (runnable2 != null) {
                        runnable2.run();
                    }
                }
            }).setCancelable(false).create();
            dialog.show();
            Button positiveButton = dialog.getButton(-1);
            Button negativeButton = dialog.getButton(-2);
            LinearLayout parent = (LinearLayout) positiveButton.getParent();
            parent.setGravity(1);
            parent.setWeightSum(2.0f);
            parent.getChildAt(1).setVisibility(8);
            ((LayoutParams) positiveButton.getLayoutParams()).weight = 1.0f;
            ((LayoutParams) negativeButton.getLayoutParams()).weight = 1.0f;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void showKeyboard(final View view) {
        view.post(new Runnable() {
            public void run() {
                view.requestFocus();
                InputMethodManager inputMethodManager = (InputMethodManager) BaseActivity.this.getSystemService("input_method");
                if (inputMethodManager != null) {
                    inputMethodManager.showSoftInput(view, 1);
                }
            }
        });
    }

    public void hideKeyboard(View view) {
        ((InputMethodManager) getSystemService("input_method")).hideSoftInputFromWindow(view.getWindowToken(), 0);
    }

    public void onSaveInstanceState(Bundle outState) {
        if (!SessionManager.getInstance().getUserJsonString().isEmpty()) {
            outState.putSerializable("userModel", SessionManager.getInstance().getUserModel());
        }
        if (!SessionManager.getInstance().getCardListJsonString().isEmpty()) {
            outState.putSerializable("cardResultModel", SessionManager.getInstance().getCardResultModel());
        }
        super.onSaveInstanceState(outState);
    }

    public boolean handleException(Exception exception, final Runnable retryRunnable, Runnable cancelRunnable) {
        if (exception instanceof NetworkException) {
            GAEvent.onGaEvent((Activity) this, (int) R.string.error, (int) R.string.network, (int) R.string.network_error);
            String string = getResources().getString(R.string.COMMON_NETWORK_ERROR_RETRY);
            if (cancelRunnable == null) {
                cancelRunnable = new Runnable() {
                    public void run() {
                    }
                };
            }
            showConfirmDialog(string, retryRunnable, cancelRunnable);
        } else if (exception instanceof ConnectTimeoutException) {
            GAEvent.onGaEvent((Activity) this, (int) R.string.error, (int) R.string.network, (int) R.string.network_timeout);
            String string2 = getResources().getString(R.string.COMMON_NETWORK_TIMEOUT_ERR);
            if (cancelRunnable == null) {
                cancelRunnable = new Runnable() {
                    public void run() {
                    }
                };
            }
            showConfirmDialog(string2, retryRunnable, cancelRunnable);
        } else if (exception instanceof SSLHandshakeException) {
            GAEvent.onGaEvent((Activity) this, (int) R.string.error, (int) R.string.network, (int) R.string.ssl_handshake_error);
            new Handler().postDelayed(new Runnable() {
                public void run() {
                    BaseActivity.this.backgroundRetryRunalbe(retryRunnable);
                }
            }, 100);
        } else if (exception instanceof UnknownHostException) {
            GAEvent.onGaEvent((Activity) this, (int) R.string.error, (int) R.string.network, (int) R.string.unknown_host_exception_error);
            new Handler().postDelayed(new Runnable() {
                public void run() {
                    BaseActivity.this.backgroundRetryRunalbe(retryRunnable);
                }
            }, 100);
        } else {
            GAEvent.onGaEvent((Activity) this, (int) R.string.error, (int) R.string.network, (int) R.string.server_error);
            showDialog(getResources().getString(R.string.COMMON_ERROR));
        }
        return true;
    }

    /* access modifiers changed from: private */
    public void backgroundRetryRunalbe(Runnable retryRunable) {
        if (retryRunable != null) {
            retryRunable.run();
        }
    }

    public boolean handleException(Exception exception, Runnable retryRunnable) {
        return handleException(exception, retryRunnable, new Runnable() {
            public void run() {
                BaseActivity.this.finish();
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        ShareatApp.getInstance().setCurrentActivity(this);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Crashlytics.log(6, "ShareAt", "Loading Activity");
        this.mLoadingDialog = new LoadingDialog(this);
        this.mLoadingDialog.setCancelable(false);
        this.mCircleDialog = new LoadingCircleDialog(this);
        this.mCircleDialog.setCancelable(false);
        this.mToast = Toast.makeText(this, "", 0);
        if (savedInstanceState != null) {
            UserModel userModel = (UserModel) savedInstanceState.getSerializable("userModel");
            if (userModel != null) {
                SessionManager.getInstance().setUserModel(userModel);
            }
            CardResultModel cardResultModel = (CardResultModel) savedInstanceState.getSerializable("cardResultModel");
            if (userModel != null) {
                SessionManager.getInstance().setCardResultModel(cardResultModel);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onRestart() {
        super.onRestart();
    }

    public boolean isApplicationSentToBackground(Context context) {
        List<RunningTaskInfo> runningTasks = ((ActivityManager) context.getSystemService("activity")).getRunningTasks(1);
        if (runningTasks.isEmpty() || runningTasks.get(0).topActivity.getPackageName().equals(context.getPackageName())) {
            return false;
        }
        return true;
    }

    public void registGpsManager() {
        if (this.mGpsManager == null) {
            try {
                this.mGpsManager = new GpsManager(this);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        ShareatApp.getInstance().setGpsManager(this.mGpsManager);
    }

    public GpsManager getGpsManager() {
        return this.mGpsManager;
    }

    public void registServiceBind() {
        if (this.mSocketManager == null) {
            this.mSocketManager = new SocketInterface(this);
        }
        this.mSocketManager.registServiceBind();
    }

    public void unregistServiceBind() {
        if (this.mSocketManager != null) {
            this.mSocketManager.unregistServiceBind();
        }
    }

    public SocketInterface getSocketManager() {
        return this.mSocketManager;
    }

    public void updateSocketUrl() {
        new SocketInfoApi(this).request(new RequestHandler() {
            public void onResult(Object result) {
                SocketResultModel model = (SocketResultModel) result;
                if (model.getResult().equals("Y")) {
                    String url = model.getSocket_info().getProtocol() + "://" + model.getSocket_info().getHost() + ":" + model.getSocket_info().getPort();
                    if (BaseActivity.this.mSocketManager != null) {
                        BaseActivity.this.mSocketManager.setSocketUrl(url);
                    }
                } else if (BaseActivity.this.mSocketManager != null) {
                    BaseActivity.this.mSocketManager.setSocketUrl(ApiUrl.SOCKET_IO_URL);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSignedCheckApi() {
        String parameter = String.format("?user_phone=%s&guid=%s", new Object[]{ShareatApp.getInstance().getPhonenumber(), ShareatApp.getInstance().getGUID()});
        SignedCheckApi request = new SignedCheckApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                SignedModel model = (SignedModel) result;
                if (!model.isSuccess() || !model.getResult().equals("Y")) {
                    BaseActivity baseActivity = BaseActivity.this;
                    String string = BaseActivity.this.getResources().getString(R.string.COMMON_NON_MEMBER_ALERT);
                    Object[] objArr = new Object[1];
                    objArr[0] = SessionManager.getInstance().isJoinUser() ? "\ub85c\uadf8\uc778" : "\ud68c\uc6d0\uac00\uc785";
                    baseActivity.showConfirmDialog(String.format(string, objArr), SessionManager.getInstance().isJoinUser() ? "\ub85c\uadf8\uc778" : "\ud68c\uc6d0\uac00\uc785", (Runnable) new Runnable() {
                        public void run() {
                            BaseActivity.this.animActivity(new Intent(BaseActivity.this, SessionManager.getInstance().isJoinUser() ? SigninActivity.class : SignupActivity.class), R.anim.fade_in_activity, R.anim.fade_out_activity);
                        }
                    });
                } else if (model.getAuth_token() != null && !model.getAuth_token().isEmpty()) {
                    GAEvent.sessionCustomDimensions(BaseActivity.this.getResources().getString(R.string.ga_intro_chk), "\ud68c\uc6d0");
                    SessionManager.getInstance().setAuthToken(model.getAuth_token());
                    SessionManager.getInstance().setJoinUser(false);
                    SessionManager.getInstance().setHasSession(true);
                    if (SessionManager.getInstance().getUserModel() == null || !SessionManager.getInstance().getUserModel().isEnablePassword()) {
                        Answers.getInstance().logLogin(new LoginEvent());
                        IgawAdbrix.retention("login");
                        BaseActivity.this.onStartMainActivity();
                        return;
                    }
                    BaseActivity.this.animActivityForResult(new Intent(BaseActivity.this, ConfirmPasswordActivity.class), 1, R.anim.modal_animation, R.anim.scale_down);
                }
            }

            public void onFinish() {
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (-1 == resultCode && 1 == requestCode) {
            AppSettingManager.getInstance().setPasswordCheck(true);
            Answers.getInstance().logLogin(new LoginEvent());
            IgawAdbrix.retention("login");
            onStartMainActivity();
        }
    }
}