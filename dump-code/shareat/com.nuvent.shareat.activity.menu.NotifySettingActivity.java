package com.nuvent.shareat.activity.menu;

import android.os.Bundle;
import android.view.View;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.NotificationApi;
import com.nuvent.shareat.event.NotifySettingEvent;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.NotificationModel;
import com.nuvent.shareat.model.NotificationResultModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.Iterator;

public class NotifySettingActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public NotificationResultModel mModel;

    public void onClickCheck(View view) {
        String notifyId;
        view.setSelected(!view.isSelected());
        switch (view.getId()) {
            case R.id.autoBranchInfoCheck /*2131296314*/:
                notifyId = "90";
                break;
            case R.id.favoriteStoreCheck /*2131296650*/:
                notifyId = "40";
                break;
            case R.id.friendCheck /*2131296682*/:
                notifyId = "70";
                break;
            case R.id.paymentCheck /*2131297044*/:
                notifyId = "20";
                break;
            case R.id.pushAgreement /*2131297141*/:
                notifyId = "100";
                AppSettingManager.getInstance().setKeyNonMemberPushStatus(view.isSelected());
                break;
            case R.id.qnaCheck /*2131297143*/:
                notifyId = "60";
                break;
            case R.id.recommendStoreCheck /*2131297184*/:
                notifyId = "30";
                break;
            case R.id.reviewLikeCheck /*2131297208*/:
                notifyId = "50";
                break;
            default:
                notifyId = "10";
                break;
        }
        onCheckView(notifyId, view.isSelected());
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_notify_setting, 2);
        GAEvent.onGAScreenView(this, R.string.ga_notify_setting);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle(getResources().getString(R.string.notify));
        this.mModel = new NotificationResultModel();
        this.mModel.setResult_list((ArrayList) getIntent().getSerializableExtra("models"));
        if (!SessionManager.getInstance().hasSession()) {
            findViewById(R.id.NonUserNotifySetting).setVisibility(0);
            findViewById(R.id.JoinUserNotifySetting).setVisibility(8);
        }
        setCheckView(this.mModel);
    }

    private void onCheckView(String notifyId, boolean isOn) {
        Iterator<NotificationModel> it = this.mModel.getResult_list().iterator();
        while (it.hasNext()) {
            NotificationModel notifyModel = it.next();
            if (notifyModel.getNotice_id().equals(notifyId)) {
                notifyModel.setUse_yn(isOn ? "Y" : "N");
            }
        }
        if (true == SessionManager.getInstance().hasSession()) {
            requestSetNotificationApi();
        } else {
            requestNonUserNotificationApi();
        }
    }

    private void setCheckView(NotificationResultModel model) {
        Iterator<NotificationModel> it = model.getResult_list().iterator();
        while (it.hasNext()) {
            NotificationModel notifyModel = it.next();
            if (notifyModel.getNotice_id().equals("20")) {
                findViewById(R.id.paymentCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("30")) {
                findViewById(R.id.recommendStoreCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("40")) {
                findViewById(R.id.favoriteStoreCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("50")) {
                findViewById(R.id.reviewLikeCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("60")) {
                findViewById(R.id.qnaCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("70")) {
                findViewById(R.id.friendCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("90")) {
                findViewById(R.id.autoBranchInfoCheck).setSelected(notifyModel.getUse_yn().equals("Y"));
            } else if (notifyModel.getNotice_id().equals("100")) {
                findViewById(R.id.pushAgreement).setSelected(notifyModel.getUse_yn().equals("Y"));
            }
        }
    }

    /* access modifiers changed from: private */
    public void requestNonUserNotificationApi() {
        NotificationApi request = new NotificationApi(this, 2, SessionManager.getInstance().hasSession());
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        request.addParam("list", this.mModel.getRequestParam());
        request.request(new RequestHandler() {
            public void onResult(Object result) {
            }

            public void onFinish() {
                super.onFinish();
                EventBus.getDefault().post(new NotifySettingEvent(NotifySettingActivity.this.mModel));
            }

            public void onFailure(Exception exception) {
                NotifySettingActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        NotifySettingActivity.this.requestNonUserNotificationApi();
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestSetNotificationApi() {
        NotificationApi request = new NotificationApi(this, 2, SessionManager.getInstance().hasSession());
        request.addParam("list", this.mModel.getRequestParam());
        request.request(new RequestHandler() {
            public void onResult(Object result) {
            }

            public void onFinish() {
                super.onFinish();
                EventBus.getDefault().post(new NotifySettingEvent(NotifySettingActivity.this.mModel));
            }

            public void onFailure(Exception exception) {
                NotifySettingActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        NotifySettingActivity.this.requestSetNotificationApi();
                    }
                });
            }
        });
    }
}