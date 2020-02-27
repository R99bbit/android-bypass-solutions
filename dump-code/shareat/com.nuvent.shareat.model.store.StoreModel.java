package com.nuvent.shareat.model.store;

import android.text.TextUtils;
import com.facebook.appevents.AppEventsConstants;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.nuvent.shareat.util.DateUtil;
import java.io.Serializable;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Map;

public class StoreModel implements Serializable {
    public String additionalDesc = "";
    public String appPayYn = "";
    public String areaId = "";
    public String areaName = "";
    public String autoBranchYn = "N";
    private String boldText;
    public String categoryId = "";
    public String categoryName = "";
    public Boolean chk_review = Boolean.valueOf(false);
    public String cntAppPay = "";
    public String cntFavorite = "";
    public String cntPay = "";
    public String cntPosPay = "";
    public String cntReview = "";
    public String couponGroupSno;
    private String couponInfo;
    public String couponName;
    public String couponType;
    private final int day = 86400;
    private int dcRate;
    public int discountValue;
    public String distance = "";
    public String dongName = "";
    public String eventContents = "";
    public String eventFileUrl = "";
    public String eventGubun = "";
    public String eventRegDate = "";
    public String eventSummaryInfo = "";
    public String eventTerm = "";
    public String eventThumbnailUrl = "";
    public String eventUserName = "";
    public String eventUserProfileImg = "";
    public String eventUserSno = "";
    private String explainText;
    public String favoriteYn = "";
    private String headListKind;
    private double hitCnt;
    public String hitYn = "";
    private final int hour = 3600;
    public String iconPath = "";
    public String issueCnt;
    private String lastName;
    private String lastUserSno;
    public String listImg = "";
    public String mainImgPath = "";
    public String mapX = "";
    public String mapY = "";
    private String method;
    private final int minute = 60;
    public String openYn = "";
    public String partnerName1 = "";
    public String partnerSno = "";
    public String partnerType = "";
    public String payMethod = "";
    public String payViewYn = "";
    public String payYn = "";
    private ArrayList<String> profileImgList = new ArrayList<>();
    public String recentCntAppPay = "";
    public String recentCntFavorite = "";
    public String recentCntPay = "";
    public String recentCntPosPay = "";
    public String recentCntReview = "";
    private int recent_cnt_feed_sno;
    public String roadAddr1 = "";
    public String roadAddr2 = "";
    public String rowNum = "";
    private float termEvent;

    public String getHeadListKind() {
        return this.headListKind == null ? "M" : this.headListKind;
    }

    public String getLastName() {
        return this.lastName;
    }

    public String getLastuserSno() {
        return this.lastUserSno;
    }

    public ArrayList<String> getProfileImgList() {
        return this.profileImgList;
    }

    public String getBoldText() {
        return this.boldText;
    }

    public String getExplainText() {
        return this.explainText;
    }

    public boolean isPayView() {
        return this.payViewYn != null && this.payViewYn.equals(AppEventsConstants.EVENT_PARAM_VALUE_YES);
    }

    public boolean isEventPartner() {
        return this.partnerType != null && this.partnerType.equals("E");
    }

    public String getAdditionalDesc() {
        return this.additionalDesc;
    }

    public void setBarcode(boolean isBarcode) {
        this.payMethod = isBarcode ? "BARCODE" : "APP";
    }

    public boolean isBarcode() {
        return this.payMethod != null && this.payMethod.equals("BARCODE");
    }

    public String getPaymentMethodType() {
        return this.payMethod;
    }

    public void setPaymentMethodType(String payMethod2) {
        this.payMethod = payMethod2;
    }

    public int getDiscountValue() {
        return this.discountValue;
    }

    public String getCouponType() {
        return this.couponType;
    }

    public String getCouponGroupSno() {
        return this.couponGroupSno;
    }

    public String getCouponName() {
        return this.couponName;
    }

    public String getIssueCnt() {
        return this.issueCnt;
    }

    public boolean isOpenYn() {
        return this.openYn != null && AppEventsConstants.EVENT_PARAM_VALUE_NO.equals(this.openYn);
    }

    public String getMainImgUrl() {
        if (this.eventFileUrl != null && !"".equals(this.eventFileUrl)) {
            return this.eventFileUrl;
        }
        if (this.mainImgPath == null || "".equals(this.mainImgPath)) {
            return "";
        }
        return this.mainImgPath;
    }

    public String getEventUserType() {
        if ("20".equals(this.eventGubun)) {
            return "\uc624\ud504\ub77c\uc778 \uace0\uac1d\ub2d8";
        }
        if ("21".equals(this.eventGubun)) {
            return "\uc624\ud504\ub77c\uc778 \uace0\uac1d\ub2d8";
        }
        if ("99".equals(this.eventGubun)) {
            return "Share@";
        }
        if ("AI".equals(this.eventGubun)) {
            return "Share@";
        }
        if (this.eventUserName == null) {
            return "\uc624\ud504\ub77c\uc778 \uace0\uac1d\ub2d8";
        }
        return this.eventUserName + "\ub2d8";
    }

    public boolean isVisibleProfileImg() {
        if (!"21".equals(this.eventGubun) && !"99".equals(this.eventGubun) && !"AI".equals(this.eventGubun) && !"".equals(this.eventGubun) && this.eventUserName != null) {
            return true;
        }
        return false;
    }

    public Boolean isFirstStore() {
        if (this.eventGubun == null || !"99AI".contains(this.eventGubun)) {
            return Boolean.valueOf(false);
        }
        return Boolean.valueOf(true);
    }

    public String getStoreAddr() {
        return this.roadAddr1 + " " + this.roadAddr2;
    }

    public String getEventGubunStr() {
        String str = "\uacb0\uc81c";
        try {
            if (this.eventGubun != null) {
                switch (Integer.parseInt(this.eventGubun)) {
                    case 30:
                        str = "\ub9ac\ubdf0";
                        break;
                    case 99:
                        str = "\ub4f1\ub85d";
                        break;
                }
            }
        } catch (Exception e) {
            System.out.println(this.eventGubun);
        }
        if ("AI".equals(this.eventGubun)) {
            return "\ub4f1\ub85d";
        }
        return str;
    }

    public int getAppPayNHitYn() {
        if (getHitYn()) {
            return 2;
        }
        if (getAppPayYn()) {
            return 1;
        }
        return 0;
    }

    public boolean getHitYn() {
        if (this.hitYn != null && this.hitYn.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            return true;
        }
        return false;
    }

    public boolean getAppPayYn() {
        if (TextUtils.isEmpty(this.appPayYn) || !this.appPayYn.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            return false;
        }
        return true;
    }

    public boolean getFavoriteYn() {
        if (this.favoriteYn != null && this.favoriteYn.equals("Y")) {
            return true;
        }
        return false;
    }

    public void setFavorite(boolean isFavorite) {
        this.favoriteYn = isFavorite ? "Y" : "N";
    }

    public void setFavorite(String isFavorite) {
        this.favoriteYn = isFavorite;
    }

    public String getReviewCount() {
        return onDecimalFormat(this.cntReview);
    }

    public String getRecentPayCount() {
        return onDecimalFormat(this.recentCntPay);
    }

    public String getDistanceMark() {
        String result_int = onDecimalFormat(this.distance);
        int repliceInt = Integer.parseInt(this.distance);
        if (repliceInt < 1000) {
            return result_int + "m";
        }
        if (repliceInt < 1000) {
            return "";
        }
        return new DecimalFormat("#.#").format((double) (((float) (repliceInt / 100)) / 10.0f)) + "Km";
    }

    public String onDecimalFormat(String value) {
        return new DecimalFormat("#,###").format((long) Integer.parseInt(value));
    }

    public StoreModel fromLink(String linked) {
        Map<String, String> map = (Map) new GsonBuilder().create().fromJson(linked, new TypeToken<Map<String, String>>() {
        }.getType());
        this.favoriteYn = map.get("favoriteYn");
        this.partnerSno = map.get("partnerSno");
        this.mapX = map.get("mapX");
        this.mapY = map.get("mapY");
        this.partnerName1 = map.get("partnerName1");
        this.roadAddr1 = map.get("roadAddr1");
        this.mainImgPath = map.get("mainImgPath");
        return this;
    }

    public int getDcRate() {
        return this.dcRate;
    }

    public String getPartnerSno() {
        return this.partnerSno;
    }

    public String getPartnerName1() {
        return this.partnerName1;
    }

    public String getDistance() {
        return this.distance == null ? AppEventsConstants.EVENT_PARAM_VALUE_NO : this.distance;
    }

    public String getIconPath() {
        return this.iconPath;
    }

    public String getCategoryName() {
        return this.categoryName;
    }

    public String getDongName() {
        return this.dongName;
    }

    public String getCntPay() {
        return this.cntPay;
    }

    public String getEventContents() {
        return this.eventContents;
    }

    public String getEventUserSno() {
        return this.eventUserSno;
    }

    public String getEventUserName() {
        return this.eventUserName;
    }

    public String getEventUserProfileImg() {
        return this.eventUserProfileImg;
    }

    public String[] getTermEvent() {
        return DateUtil.getEventTime(this.termEvent);
    }

    public String getAreaId() {
        return this.areaId;
    }

    public String getAreaName() {
        return this.areaName;
    }

    public String getCategoryId() {
        return this.categoryId;
    }

    public String getCntAppPay() {
        return this.cntAppPay;
    }

    public String getCntFavorite() {
        return this.cntFavorite;
    }

    public String getCntPosPay() {
        return this.cntPosPay;
    }

    public String getCntReview() {
        return this.cntReview;
    }

    public String getEventFileUrl() {
        return this.eventFileUrl;
    }

    public String getEventGubun() {
        return this.eventGubun;
    }

    public String getEventRegDate() {
        return this.eventRegDate;
    }

    public String getEventSummaryInfo() {
        return this.eventSummaryInfo;
    }

    public String getEventTerm() {
        return this.eventTerm;
    }

    public String getEventThumbnailUrl() {
        return this.eventThumbnailUrl;
    }

    public double getHitCnt() {
        return this.hitCnt;
    }

    public String getMainImgPath() {
        return this.mainImgPath;
    }

    public String getMapX() {
        return this.mapX;
    }

    public String getMapY() {
        return this.mapY;
    }

    public String getOpenYn() {
        return this.openYn;
    }

    public int getRecent_cnt_feed_sno() {
        return this.recent_cnt_feed_sno;
    }

    public String getRecentCntAppPay() {
        return this.recentCntAppPay;
    }

    public String getRecentCntFavorite() {
        return this.recentCntFavorite;
    }

    public String getRecentCntPay() {
        return this.recentCntPay;
    }

    public String getRecentCntPosPay() {
        return this.recentCntPosPay;
    }

    public String getRecentCntReview() {
        return this.recentCntReview;
    }

    public String getRoadAddr1() {
        return this.roadAddr1;
    }

    public String getRoadAddr2() {
        return this.roadAddr2;
    }

    public String getRowNum() {
        return this.rowNum;
    }

    public void setPartnerSno(String partnerSno2) {
        this.partnerSno = partnerSno2;
    }

    public void setPartnerName1(String partnerName12) {
        this.partnerName1 = partnerName12;
    }

    public String getPayYn() {
        return this.payYn;
    }

    public void setPayYn(String payYn2) {
        this.payYn = payYn2;
    }

    public String getAutoBranchYn() {
        return this.autoBranchYn;
    }

    public void setAutoBranchYn(String autoBranchYn2) {
        this.autoBranchYn = autoBranchYn2;
    }

    public String getListImg() {
        return this.listImg;
    }

    public void setDcRate(int nDcRate) {
        this.dcRate = nDcRate;
    }

    public void setCouponInfo(String couponInfo2) {
        this.couponInfo = couponInfo2;
    }

    public String getCouponInfo() {
        return this.couponInfo;
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method2) {
        this.method = method2;
    }
}