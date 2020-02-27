package com.nuvent.shareat.activity.intro;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnKeyListener;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.support.v4.view.ViewPager.PageTransformer;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout.LayoutParams;
import android.widget.Toast;
import com.gun0912.tedpermission.PermissionListener;
import com.gun0912.tedpermission.TedPermission;
import com.gun0912.tedpermission.TedPermission.Builder;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.NotificationApi;
import com.nuvent.shareat.api.intro.StartImageApi;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.NotificationModel;
import com.nuvent.shareat.model.NotificationResultModel;
import com.nuvent.shareat.model.StartImageModel;
import com.nuvent.shareat.model.StartImageResultModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import net.xenix.util.BackPressCloseHandler;
import net.xenix.util.ImageDisplay;

public class TutorialActivity extends BaseActivity {
    /* access modifiers changed from: private */
    public Dialog mAgreementDialog;
    private BackPressCloseHandler mBackPressCloseHandler;
    private int[] mIntroImages = {R.drawable.photocut_02, R.drawable.photocut_03, R.drawable.photocut_04, R.drawable.photocut_05};
    /* access modifiers changed from: private */
    public StartImageResultModel mModel;
    PermissionListener permissionlistener = new PermissionListener() {
        public void onPermissionGranted() {
            GAEvent.onGaEvent((Activity) TutorialActivity.this, (int) R.string.ga_tutorial, (int) R.string.ga_ev_click, (int) R.string.ga_tutorial_join);
            TutorialActivity.this.animActivity(new Intent(TutorialActivity.this, SessionManager.getInstance().isJoinUser() ? SigninActivity.class : SignupActivity.class), R.anim.fade_in_activity, R.anim.fade_out_activity);
            TutorialActivity.this.finish(false);
        }

        public void onPermissionDenied(List<String> list) {
        }
    };

    public class TutorialAdapter extends PagerAdapter {
        private Context mContext;
        private LayoutInflater mLayoutInflater;
        private ArrayList<StartImageModel> mModels = new ArrayList<>();
        private int[] resourceIds;

        public TutorialAdapter(Context context, ArrayList<StartImageModel> models, int[] resourceIds2) {
            this.mContext = context;
            this.mLayoutInflater = (LayoutInflater) this.mContext.getSystemService("layout_inflater");
            this.resourceIds = resourceIds2;
            this.mModels = models;
        }

        public int getCount() {
            return this.mModels.size() + this.resourceIds.length;
        }

        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        public Object instantiateItem(ViewGroup container, int position) {
            ImageView imageView = new ImageView(this.mContext);
            imageView.setScaleType(ScaleType.CENTER_CROP);
            if (this.mModels.size() == 0) {
                imageView.setImageResource(this.resourceIds[position]);
            } else if (this.mModels.size() - 1 < position) {
                imageView.setImageResource(this.resourceIds[position - this.mModels.size()]);
            } else {
                ImageDisplay.getInstance().displayImageLoad(this.mModels.get(position).getImg_path(), imageView);
            }
            container.addView(imageView);
            return imageView;
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }
    }

    public class TutorialPageTransformer implements PageTransformer {
        public TutorialPageTransformer() {
        }

        public void transformPage(View page, float position) {
            if (position >= -1.0f && position > 0.0f && position <= 1.0f) {
                float normalizedposition = Math.abs(Math.abs(position) - 1.0f);
                page.setScaleX((normalizedposition / 2.0f) + 0.5f);
                page.setScaleY((normalizedposition / 2.0f) + 0.5f);
                page.setAlpha(normalizedposition);
            }
        }
    }

    public void onBackPressed() {
        this.mBackPressCloseHandler.onBackPressed();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tutorial);
        GAEvent.onGAScreenView(this, R.string.ga_tutorial);
        this.mBackPressCloseHandler = new BackPressCloseHandler(this);
        ((Button) findViewById(R.id.startButton)).setText("\ub85c\uadf8\uc778/\ud68c\uc6d0\uac00\uc785");
        findViewById(R.id.startButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                ((Builder) ((Builder) TedPermission.with(TutorialActivity.this).setPermissionListener(TutorialActivity.this.permissionlistener)).setPermissions("android.permission.READ_PHONE_STATE")).check();
            }
        });
        findViewById(R.id.passButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                AppSettingManager.getInstance().setStartActivity(true);
                GAEvent.sessionCustomDimensions(TutorialActivity.this.getResources().getString(R.string.ga_tutorial), "\ube44\ud68c\uc6d0");
                GAEvent.onGaEvent((Activity) TutorialActivity.this, (int) R.string.ga_tutorial, (int) R.string.ga_ev_click, (int) R.string.ga_tutorial_non_member);
                SessionManager.getInstance().setHasSession(false);
                TutorialActivity.this.onStartMainActivity();
            }
        });
        if (true == AppSettingManager.getInstance().isShowPushAgreementDialog()) {
            requestStartImageList();
        } else {
            showNonMemberPushAgreementDialog();
        }
    }

    /* access modifiers changed from: private */
    public void setViewPager() {
        ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.setAdapter(new TutorialAdapter(this, this.mModel.getResult_list(), this.mIntroImages));
        viewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
                TutorialActivity.this.setPageIndicator(position);
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
        viewPager.setOffscreenPageLimit(this.mModel.getResult_list().size() + this.mIntroImages.length);
        ViewGroup viewGroup = (ViewGroup) findViewById(R.id.indicatorLayout);
        for (int i = 0; i < this.mModel.getResult_list().size() + this.mIntroImages.length; i++) {
            LayoutParams params = new LayoutParams(-2, -2);
            if (i > 0) {
                params.leftMargin = getResources().getDimensionPixelOffset(R.dimen.TUTORIAL_INDICATOR_MARGIN);
            }
            ImageView view = new ImageView(this);
            view.setImageResource(R.drawable.selector_new_tutorial_icon);
            view.setLayoutParams(params);
            viewGroup.addView(view);
        }
        viewGroup.getChildAt(0).setSelected(true);
    }

    /* access modifiers changed from: private */
    public void setPageIndicator(int position) {
        ViewGroup viewGroup = (ViewGroup) findViewById(R.id.indicatorLayout);
        int i = 0;
        while (i < viewGroup.getChildCount()) {
            viewGroup.getChildAt(i).setSelected(position == i);
            i++;
        }
    }

    public void requestStartImageList() {
        new StartImageApi(this).request(new RequestHandler() {
            public void onStart() {
                TutorialActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                TutorialActivity.this.showCircleDialog(false);
                TutorialActivity.this.mModel = (StartImageResultModel) result;
                TutorialActivity.this.setViewPager();
            }

            public void onFailure(Exception exception) {
                TutorialActivity.this.showCircleDialog(false);
            }

            public void onFinish() {
                TutorialActivity.this.showCircleDialog(false);
            }
        });
    }

    private void showNonMemberPushAgreementDialog() {
        this.mAgreementDialog = new Dialog(this);
        this.mAgreementDialog.requestWindowFeature(1);
        this.mAgreementDialog.getWindow().clearFlags(2);
        this.mAgreementDialog.getWindow().setDimAmount(0.5f);
        this.mAgreementDialog.getWindow().setFlags(32, 32);
        this.mAgreementDialog.setContentView(R.layout.image_alert_layer);
        this.mAgreementDialog.show();
        AppSettingManager.getInstance().setShowPushAgreementDialog(true);
        this.mAgreementDialog.setOnKeyListener(new OnKeyListener() {
            public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
                if (keyCode == 4) {
                    return true;
                }
                return false;
            }
        });
        this.mAgreementDialog.findViewById(R.id.not_accept).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                TutorialActivity.this.requestStartImageList();
                AppSettingManager.getInstance().setKeyNonMemberPushStatus(false);
                TutorialActivity.this.requestNonUserNotificationApi(2);
                TutorialActivity.this.mAgreementDialog.dismiss();
            }
        });
        this.mAgreementDialog.findViewById(R.id.accept).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                TutorialActivity.this.requestStartImageList();
                AppSettingManager.getInstance().setKeyNonMemberPushStatus(true);
                TutorialActivity.this.mAgreementDialog.dismiss();
                Calendar c = Calendar.getInstance();
                Toast.makeText(TutorialActivity.this.getBaseContext(), (((String.valueOf(c.get(1)) + "\ub144 ") + String.format("%02d", new Object[]{Integer.valueOf(c.get(2) + 1)}) + "\uc6d4 ") + String.format("%02d", new Object[]{Integer.valueOf(c.get(5))}) + "\uc77c") + " \uc815\ubcf4 \uc54c\ub9bc \ub3d9\uc758\ub97c \ud558\uc168\uc2b5\ub2c8\ub2e4", 1).show();
                TutorialActivity.this.requestNonUserNotificationApi(2);
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestNonUserNotificationApi(final int requestType) {
        NotificationApi request = new NotificationApi(this, requestType, SessionManager.getInstance().hasSession());
        request.addParam("guid", ShareatApp.getInstance().getGUID());
        NotificationResultModel notificationModel = new NotificationResultModel();
        ArrayList<NotificationModel> arrNotificationModel = new ArrayList<>();
        NotificationModel pushAgreeModel = new NotificationModel();
        pushAgreeModel.setUse_yn(true == AppSettingManager.getInstance().getKeyNonMemberPushStatus() ? "Y" : "N");
        pushAgreeModel.setNotice_id("100");
        arrNotificationModel.add(pushAgreeModel);
        notificationModel.setResult_list(arrNotificationModel);
        request.addParam("list", notificationModel.getRequestParam());
        request.request(new RequestHandler() {
            public void onResult(Object result) {
            }

            public void onFinish() {
                super.onFinish();
            }

            public void onFailure(Exception exception) {
                TutorialActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        TutorialActivity.this.requestNonUserNotificationApi(requestType);
                    }
                });
            }
        });
    }
}