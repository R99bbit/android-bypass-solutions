package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ListView;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.InviteEvent;
import com.facebook.appevents.AppEventsConstants;
import com.gun0912.tedpermission.PermissionListener;
import com.igaworks.adbrix.IgawAdbrix;
import com.kakao.kakaolink.AppActionBuilder;
import com.kakao.kakaolink.AppActionInfoBuilder;
import com.kakao.kakaolink.KakaoLink;
import com.kakao.kakaolink.KakaoTalkLinkMessageBuilder;
import com.kakao.util.KakaoParameterException;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.adapter.friend.AddressAdapter;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.AddressListApi;
import com.nuvent.shareat.event.AddressStateEvent;
import com.nuvent.shareat.event.FriendAddEvent;
import com.nuvent.shareat.manager.AddressManager;
import com.nuvent.shareat.model.friend.FriendModel;
import com.nuvent.shareat.model.friend.FriendResultModel;
import com.nuvent.shareat.service.AddressService;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.ShareAtUtil;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.List;

public class AddAddressActivity extends MainActionBarActivity {
    private AddressAdapter mAddressAdapter;
    private ArrayList<FriendModel> mFriendModels;
    PermissionListener permissionlistener = new PermissionListener() {
        public void onPermissionGranted() {
            if (!AddAddressActivity.this.isServiceRunningCheck()) {
                AddAddressActivity.this.startService(new Intent(AddAddressActivity.this, AddressService.class));
            } else {
                AddAddressActivity.this.updateAddress();
            }
        }

        public void onPermissionDenied(List<String> list) {
            AddAddressActivity.this.finish();
        }
    };

    public void onEventMainThread(FriendAddEvent event) {
        if (event.getTargetSno() != null && !event.getTargetSno().isEmpty()) {
            int i = 0;
            while (true) {
                if (i >= this.mFriendModels.size()) {
                    break;
                } else if (this.mFriendModels.get(i).getUser_sno().equals(event.getTargetSno())) {
                    this.mFriendModels.get(i).setFollow_status(event.getFollowStatus());
                    break;
                } else {
                    i++;
                }
            }
            this.mAddressAdapter.notifyDataSetChanged();
        }
    }

    public void onEventMainThread(AddressStateEvent event) {
        if (event != null) {
            boolean isNOUser = false;
            this.mFriendModels.clear();
            if (event.getState() == 3) {
                ArrayList<FriendModel> models = event.getModel();
                this.mFriendModels = models;
                this.mAddressAdapter.dataClear();
                if (models.size() > 0) {
                    this.mAddressAdapter.addSeparatorItem(0);
                    for (int i = 0; i < models.size(); i++) {
                        FriendModel model = models.get(i);
                        if (!isNOUser && model.getUser_sno() == null && i > 0) {
                            this.mAddressAdapter.addFirstSeparatorItem(i);
                            this.mAddressAdapter.addSeparatorItem(models.size() - i);
                            isNOUser = true;
                        }
                        this.mAddressAdapter.setData(model);
                    }
                    if (!isNOUser) {
                        this.mAddressAdapter.addFirstSeparatorItem(models.size());
                    }
                }
            }
            this.mAddressAdapter.notifyDataSetChanged();
        }
    }

    public void onClickKakaoShare(View view) {
        GAEvent.onGaEvent(getResources().getString(R.string.ga_friends_add_friend), getResources().getString(R.string.ga_ev_invite), getResources().getString(R.string.ga_add_friends_kakao));
        String shareText = ShareAtUtil.getSharedUrl(0);
        try {
            KakaoLink kakaoLink = KakaoLink.getKakaoLink(this);
            KakaoTalkLinkMessageBuilder messageBuilder = kakaoLink.createKakaoTalkLinkMessageBuilder();
            messageBuilder.addText(shareText).addImage("http://file.shareat.me//Upload/img/shareatme/kakao_shareat_thumb_.png", 622, 544).addWebLink("http://www.shareat.me", "http://www.shareat.me").addAppButton("\uc250\uc5b4\uc573 \uc2dc\uc791\ud558\uae30", new AppActionBuilder().addActionInfo(AppActionInfoBuilder.createAndroidActionInfoBuilder().setMarketParam("referrer=utm_source%3Dkakaolink%26utm_medium%3Dapp_android%26utm_campaign%3Dinvite").build()).addActionInfo(AppActionInfoBuilder.createiOSActionInfoBuilder().build()).build());
            kakaoLink.sendMessage(messageBuilder.build(), this);
            Answers.getInstance().logInvite(new InviteEvent().putMethod("kakaotalk"));
            IgawAdbrix.retention("invite", "kakaotalk");
        } catch (KakaoParameterException e) {
            e.printStackTrace();
        }
    }

    /* access modifiers changed from: private */
    public void updateAddress() {
        AddressListApi request = new AddressListApi(this);
        request.addParam("page", AppEventsConstants.EVENT_PARAM_VALUE_YES);
        request.request(new RequestHandler() {
            public void onStart() {
                AddAddressActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                FriendResultModel model = (FriendResultModel) result;
                if (model.getResult().equals("Y") && model.getResult_list().size() > 0) {
                    AddressManager.getInstance(AddAddressActivity.this).insertUserAddress(model.getResult_list());
                    AddressManager.getInstance(AddAddressActivity.this).updateAddress(model.getResult_list());
                }
                AddAddressActivity.this.requestAddressApi();
                AddAddressActivity.this.showCircleDialog(false);
            }

            public void onFailure(Exception exception) {
                AddAddressActivity.this.showCircleDialog(false);
                AddAddressActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        AddAddressActivity.this.updateAddress();
                    }
                });
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_address, 2);
        GAEvent.onGaEvent((Activity) this, (int) R.string.friend_group, (int) R.string.ga_ev_click, (int) R.string.ga_friends_add_friend);
        GAEvent.onGAScreenView(this, R.string.ga_friends_add_friend);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\uce5c\uad6c\ucd94\uac00");
        this.mFriendModels = new ArrayList<>();
        this.mAddressAdapter = new AddressAdapter(this);
        ((ListView) findViewById(R.id.listView)).setAdapter(this.mAddressAdapter);
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
    }

    /* access modifiers changed from: private */
    public void requestAddressApi() {
        AddressManager.getInstance(this).getAllDBAddress();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        super.onStop();
    }

    public boolean isServiceRunningCheck() {
        String serviceName = AddressService.class.getName();
        for (RunningServiceInfo service : ((ActivityManager) getSystemService("activity")).getRunningServices(ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED)) {
            if (serviceName.equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }
}