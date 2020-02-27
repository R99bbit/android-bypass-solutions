package com.nuvent.shareat.receiver;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import com.facebook.appevents.AppEventsConstants;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.common.BranchInfoActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.PaymentHistoryApi;
import com.nuvent.shareat.api.common.LoplatUserTrackingAPI;
import com.nuvent.shareat.api.store.StoreApi;
import com.nuvent.shareat.event.AutoBranchEvent;
import com.nuvent.shareat.manager.LoplatManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.LoplatUserTrackingModel;
import com.nuvent.shareat.model.MyPaymentModel;
import com.nuvent.shareat.model.external.LoplatConfigModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.model.store.StoreDetailResultModel;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.ShareatLogger;
import de.greenrobot.event.EventBus;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;

public class ShareatLoplatBroadcastReceiver extends BroadcastReceiver {
    /* access modifiers changed from: private */
    public static int retryCnt = 0;
    private final int MAX_RETRY_CNT = 5;
    LoplatUserTrackingModel loplatUserTrackingModel = null;
    public String mClientCode = null;
    /* access modifiers changed from: private */
    public Context mContext = null;
    private int mEvent = 0;
    private double mLat = 37.4986366d;
    private double mLng = 127.027021d;
    /* access modifiers changed from: private */
    public int mPlaceType = 0;

    static /* synthetic */ int access$608() {
        int i = retryCnt;
        retryCnt = i + 1;
        return i;
    }

    public void onReceive(Context context, Intent intent) {
        int nPartnerSno;
        if (intent.getAction().equals("com.nuvent.shareat.response")) {
            int type = intent.getIntExtra(KakaoTalkLinkProtocol.ACTION_TYPE, 0);
            this.mPlaceType = type;
            this.mContext = context;
            this.mClientCode = intent.getStringExtra("clientCode");
            this.mEvent = intent.getIntExtra("event", 0);
            String strPartnerName = intent.getStringExtra("partnerName");
            if (!(strPartnerName == null || true == strPartnerName.isEmpty() || true == strPartnerName.contains("unknown"))) {
                this.loplatUserTrackingModel = null;
                this.loplatUserTrackingModel = new LoplatUserTrackingModel();
                this.loplatUserTrackingModel.setLog_type("loplat_lbs");
                double dLat = intent.getDoubleExtra("userX", 37.4986366d);
                this.mLat = dLat;
                double dLng = intent.getDoubleExtra("userY", 127.027021d);
                this.mLng = dLng;
                this.loplatUserTrackingModel.setUser_x(dLat);
                this.loplatUserTrackingModel.setUser_y(dLng);
                String partnerSno = intent.getStringExtra("clientCode");
                if (partnerSno == null || true == partnerSno.isEmpty()) {
                    partnerSno = AppEventsConstants.EVENT_PARAM_VALUE_NO;
                }
                try {
                    nPartnerSno = Integer.parseInt(partnerSno);
                } catch (NumberFormatException e) {
                    nPartnerSno = 0;
                }
                this.loplatUserTrackingModel.setPartner_sno(nPartnerSno);
                this.loplatUserTrackingModel.setTags(intent.getStringExtra("tags"));
                this.loplatUserTrackingModel.setCategory_name(intent.getStringExtra("categoryName"));
                this.loplatUserTrackingModel.setVersion(ShareatApp.getInstance().getAppVersionName());
                this.loplatUserTrackingModel.setPhone_os("A");
                this.loplatUserTrackingModel.setPartner_name(intent.getStringExtra("partnerName"));
                String place = this.mEvent == 2 ? "L" : intent.getIntExtra("enterType", 0) == 0 ? "E" : "L";
                this.loplatUserTrackingModel.setPlace(place);
                requestLoplatUserTrackingApi(this.loplatUserTrackingModel);
            }
            if (2 == type) {
                LoplatManager.getInstance(this.mContext).clearData();
                ShareatLogger.writeLog("[DEBUG] loplatmanager clear data!!");
                int enterType = intent.getIntExtra("enterType", 0);
                this.mEvent = enterType;
                if (this.mEvent == 2 || (this.mEvent == 1 && enterType == 1)) {
                    ShareatLogger.writeLog("[DEBUG] Leave place.....");
                    return;
                }
                ShareatLogger.writeLog("[DEBUG] Enter place.....");
            }
            if (!SessionManager.getInstance().hasSession()) {
                ShareatLogger.writeLog("[DEBUG] Session Value is empty..");
            } else if (this.mClientCode == null || true == this.mClientCode.isEmpty() || true == AppEventsConstants.EVENT_PARAM_VALUE_NO.equals(this.mClientCode)) {
                ShareatLogger.writeLog("[DEBUG] partner_sno is empty..");
                LoplatManager.getInstance(this.mContext).setSearchingStatus(1);
            } else if (!AppSettingManager.getInstance().getIsEnableAutoBranchPopupValue()) {
                requestPushStoreDetailApi(this.mClientCode);
            } else {
                requestMyPaymentListApi();
            }
        }
    }

    private void requestMyPaymentListApi() {
        SimpleDateFormat format = new SimpleDateFormat(StoreInstaModel.MESSAGE_CARD_TIME_FORMAT, Locale.getDefault());
        Calendar c = Calendar.getInstance();
        new PaymentHistoryApi(this.mContext, ApiUrl.PAMENT_HISTORY + "?page=" + AppEventsConstants.EVENT_PARAM_VALUE_YES + "&view_cnt=" + AppEventsConstants.EVENT_PARAM_VALUE_YES + "&order_asc=" + "DESC" + "&search_start=" + format.format(c.getTime()) + "&search_end=" + format.format(c.getTime())).request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                JsonArray objects = (JsonArray) result;
                if (objects.size() == 0) {
                    ShareatLogger.writeLog("[DEBUG] My payment history not exists");
                    ShareatLoplatBroadcastReceiver.this.requestPushStoreDetailApi(ShareatLoplatBroadcastReceiver.this.mClientCode);
                    return;
                }
                boolean bIsExistPaymentHistory = false;
                String strPaydateText = null;
                Iterator<JsonElement> it = objects.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    MyPaymentModel model = (MyPaymentModel) new Gson().fromJson(it.next(), MyPaymentModel.class);
                    if (model.pay_status == 20 && true == ShareatLoplatBroadcastReceiver.this.mClientCode.equals(model.partner_sno)) {
                        bIsExistPaymentHistory = true;
                        strPaydateText = model.getPay_date_text();
                        break;
                    }
                }
                if (true != bIsExistPaymentHistory || ShareatLoplatBroadcastReceiver.this.IsNotifyAutoBranchPopup(strPaydateText)) {
                    ShareatLoplatBroadcastReceiver.this.requestPushStoreDetailApi(ShareatLoplatBroadcastReceiver.this.mClientCode);
                } else {
                    ShareatLogger.writeLog("[DEBUG] Recent payment history exists : " + strPaydateText);
                }
            }

            public void onFailure(Exception exception) {
            }

            public void onFinish() {
            }
        });
    }

    public boolean IsNotifyAutoBranchPopup(String strLastPayDate) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss", Locale.getDefault());
        Calendar instance = Calendar.getInstance();
        Date endDate = null;
        Date startDate = new Date(System.currentTimeMillis());
        try {
            endDate = sdf.parse(strLastPayDate);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        if ((startDate.getTime() - endDate.getTime()) / 60000 > 5) {
            return true;
        }
        return false;
    }

    /* access modifiers changed from: private */
    public void requestPushStoreDetailApi(String partnerSno) {
        String parameter = String.format("?partner_sno=%s&user_X=%s&user_Y=%s", new Object[]{partnerSno, Double.valueOf(this.mLng), Double.valueOf(this.mLat)});
        StoreApi request = new StoreApi(this.mContext);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                StoreDetailModel detailModel = ((StoreDetailResultModel) result).getStore_detail();
                StoreModel storeModel = new StoreModel();
                storeModel.partnerName1 = detailModel.getPartner_name1();
                storeModel.partnerSno = String.valueOf(detailModel.getPartner_sno());
                storeModel.setDcRate(detailModel.getDc_rate());
                storeModel.couponName = detailModel.getCouponName();
                storeModel.couponGroupSno = detailModel.getCouponGroupSno();
                storeModel.favoriteYn = detailModel.getFavorite_yn();
                storeModel.categoryName = detailModel.getCategory_name();
                storeModel.mainImgPath = detailModel.getImg_path();
                storeModel.setCouponInfo(detailModel.getCouponInfo());
                storeModel.setBarcode(detailModel.isBarcode());
                storeModel.setAutoBranchYn("Y");
                storeModel.listImg = detailModel.getListImg();
                try {
                    storeModel.distance = String.valueOf(detailModel.distance);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                storeModel.setBarcode(detailModel.isBarcode());
                ShareatLogger.writeLog("[DEBUG] Receive store detail API - partner_name1 : " + storeModel.partnerName1);
                if (storeModel.partnerName1 != null && !storeModel.partnerName1.isEmpty()) {
                    if (true == ShareatLoplatBroadcastReceiver.this.isRecentSearch(ShareatLoplatBroadcastReceiver.this.mClientCode)) {
                        ShareatLogger.writeLog("[DEBUG] recent data exist ..");
                        return;
                    }
                    LoplatManager.getInstance(ShareatLoplatBroadcastReceiver.this.mContext).clearData();
                    LoplatManager.getInstance(ShareatLoplatBroadcastReceiver.this.mContext).setStoreModel(storeModel);
                    LoplatManager.getInstance(ShareatLoplatBroadcastReceiver.this.mContext).setFindPartnerTime(new Date(System.currentTimeMillis()));
                    LoplatManager.getInstance(ShareatLoplatBroadcastReceiver.this.mContext).setFindSuccess(true);
                    if (true == ShareatLoplatBroadcastReceiver.this.isRunningProcess(ShareatLoplatBroadcastReceiver.this.mContext, ShareatLoplatBroadcastReceiver.this.mContext.getPackageName()) && !ShareatApp.getInstance().isPayFlowing()) {
                        ShareatLogger.writeLog("[DEBUG] set response data ..");
                        EventBus.getDefault().post(new AutoBranchEvent(storeModel));
                    } else if (!AppSettingManager.getInstance().getIsEnableAutoBranchPopupValue()) {
                    } else {
                        if (!AppSettingManager.getInstance().getAutoBranchPopupStatus()) {
                            ShareatLogger.writeLog("[DEBUG] AutoBranch setting is OFF @@");
                        } else if (!ShareatLoplatBroadcastReceiver.this.isValidHour()) {
                            ShareatLogger.writeLog("[DEBUG] Not valid hour..");
                        } else if (ShareatLoplatBroadcastReceiver.this.mPlaceType == 2 && true == ShareatLoplatBroadcastReceiver.this.isRecentSearch(ShareatLoplatBroadcastReceiver.this.mClientCode)) {
                            ShareatLogger.writeLog("[DEBUG] recent show BranchInfoActivity..");
                        } else if (true == LoplatManager.getInstance(ShareatLoplatBroadcastReceiver.this.mContext).getNewStart()) {
                            ShareatLogger.writeLog("[DEBUG] new application start, no show BranchInfoActivity");
                            LoplatManager.getInstance(ShareatLoplatBroadcastReceiver.this.mContext).setNewStart(false);
                        } else {
                            ShareatLoplatBroadcastReceiver.this.showAutoBranchPopup(storeModel);
                        }
                    }
                }
            }

            public void onFailure(Exception exception) {
            }
        });
    }

    /* access modifiers changed from: private */
    public boolean isRecentSearch(String partnerSno) {
        StoreModel sm = LoplatManager.getInstance(this.mContext).getStoreModel();
        if (sm != null && true == partnerSno.equals(sm.getPartnerSno())) {
            Date FindPartnerDate = LoplatManager.getInstance(this.mContext).getFindPartnerTime();
            Date currentDate = new Date(System.currentTimeMillis());
            boolean bFindSuccess = LoplatManager.getInstance(this.mContext).getFindSuccess();
            if (FindPartnerDate != null) {
                long lSearchInteval = (currentDate.getTime() - FindPartnerDate.getTime()) / 60000;
                LoplatConfigModel lcm = LoplatManager.getInstance(this.mContext).getLoplatConfigModel();
                int nPeriod = 3;
                if (lcm != null) {
                    nPeriod = lcm.getDuplicateByPassPeriod();
                }
                if (((long) nPeriod) >= lSearchInteval && true == bFindSuccess) {
                    return true;
                }
            }
        }
        return false;
    }

    /* access modifiers changed from: private */
    public boolean isValidHour() {
        int[] nValidPassHour = LoplatManager.getInstance(this.mContext).getValidPassHours();
        int nCurrentHour = Calendar.getInstance().get(11);
        for (int i = 0; i < nValidPassHour.length - 1; i++) {
            if (nCurrentHour == nValidPassHour[i]) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: private */
    public void showAutoBranchPopup(StoreModel sm) {
        Intent i = new Intent(this.mContext, BranchInfoActivity.class);
        i.setFlags(805306368);
        i.putExtra("clientCode", this.mClientCode);
        i.putExtra("model", sm);
        this.mContext.startActivity(i);
        ShareatLogger.writeLog("[DEBUG] AutoBranch activity show..");
    }

    public boolean isRunningProcess(Context context, String packageName) {
        for (RunningAppProcessInfo rap : ((ActivityManager) context.getSystemService("activity")).getRunningAppProcesses()) {
            if (rap.processName.equals(packageName)) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: private */
    public void requestLoplatUserTrackingApi(LoplatUserTrackingModel model) {
        LoplatUserTrackingAPI request = new LoplatUserTrackingAPI(this.mContext);
        request.addParam("log_type", model.getLog_type());
        request.addParam("user_x", String.valueOf(model.getUser_x()));
        request.addParam("user_y", String.valueOf(model.getUser_y()));
        request.addParam("tags", model.getTags());
        request.addParam("category_name", model.getCategory_name());
        request.addParam("version", model.getVersion());
        request.addParam("phone_os", model.getPhone_os());
        request.addParam("place", model.getPlace());
        request.addParam("partner_sno", String.valueOf(model.getPartner_sno()));
        request.addParam("partner_name", model.getPartner_name());
        request.addParam("search_type", this.mPlaceType == 2 ? "auto" : "manual");
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                super.onResult(result);
                ShareatLoplatBroadcastReceiver.retryCnt = 0;
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
                if (5 < ShareatLoplatBroadcastReceiver.retryCnt) {
                    ShareatLoplatBroadcastReceiver.retryCnt = 0;
                    return;
                }
                ShareatLogger.writeLog("[ERROR] requestLoplatUserTrackingApi Failed - " + exception.toString());
                new Handler().postDelayed(new Runnable() {
                    public void run() {
                        ShareatLogger.writeLog("[DEBUG] retry requestLoplatUserTrackingApi ");
                        ShareatLoplatBroadcastReceiver.this.requestLoplatUserTrackingApi(ShareatLoplatBroadcastReceiver.this.loplatUserTrackingModel);
                        ShareatLoplatBroadcastReceiver.access$608();
                    }
                }, 1000);
            }
        });
    }
}