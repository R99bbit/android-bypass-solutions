package com.nuvent.shareat.model.store;

import android.content.Context;
import android.text.TextUtils;
import com.facebook.appevents.AppEventsConstants;
import com.google.gson.GsonBuilder;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class StoreDetailModel implements Serializable {
    public String addr_1;
    public String addr_2;
    public String app_pay_yn;
    public String break_time;
    public String category_name;
    public Boolean chk_review = Boolean.valueOf(false);
    public int cnt_favorite;
    public int cnt_review;
    public int cnt_view;
    public String couponGroupSno;
    private String couponInfo;
    public String couponName;
    public String couponType;
    private final int day = 86400;
    public int dc_rate;
    private String detailContentsImgs;
    public int discountValue;
    public int distance;
    public String dongName;
    public String eventContents;
    public String eventGubun;
    public String eventRegDate;
    public String eventSummaryInfo;
    public String eventTerm;
    public String eventUserName;
    public String eventUserProfileImg;
    public String eventUserSno;
    public String favorite_yn;
    public String hash_tag;
    public String hollyday;
    private final int hour = 3600;
    public String img_path;
    public String issueCnt;
    public double katec_map_x;
    public double katec_map_y;
    public String link_url;
    public String listImg = "";
    public double map_x;
    public double map_y;
    private String method;
    private final int minute = 60;
    public String openYn;
    public String parking_type;
    public String parking_yn;
    public String partnerType;
    public String partner_introduce;
    public String partner_name1;
    public String partner_name2;
    public int partner_sno;
    public String payMethod = "";
    private String payViewYn;
    public int pay_cnt;
    public String road_addr_1;
    public String road_addr_2;
    public String sales_time;
    public String service_name;
    public String service_type_name;
    public String shop_way;
    public String tel01;
    public String tel02;
    public String termEvent;
    public String traffinc_info;
    private String useBizChat;
    private String useBizChatURL;
    public int vogue_cnt;

    public String getPayViewYn() {
        return this.payViewYn == null ? AppEventsConstants.EVENT_PARAM_VALUE_YES : this.payViewYn;
    }

    public boolean isEventPartner() {
        return this.partnerType != null && this.partnerType.equals("E");
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

    public String getIssueCnt() {
        return this.issueCnt;
    }

    public String getCouponGroupSno() {
        return this.couponGroupSno;
    }

    public String getCouponName() {
        return this.couponName;
    }

    public String[] getEventTimeFormat() {
        StringBuilder sb = new StringBuilder();
        try {
            int termEventInt = Integer.parseInt(this.termEvent);
            if (termEventInt < 60) {
                sb.append(termEventInt + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
                sb.append("\ucd08\uc804");
            } else if (termEventInt < 3600) {
                sb.append(Math.round((float) (termEventInt / 60)) + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
                sb.append("\ubd84\uc804");
            } else if (termEventInt < 86400) {
                sb.append(Math.round((float) (termEventInt / 3600)) + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
                sb.append("\uc2dc\uac04\uc804");
            } else {
                sb.append(Math.round((float) (termEventInt / 86400)) + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
                sb.append("\uc77c\uc804");
            }
        } catch (Exception e) {
        }
        return sb.toString().split(EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR);
    }

    public String eventMsg() {
        if (this.eventGubun == null || "30".contains(this.eventGubun) || "31".contains(this.eventGubun)) {
            return this.eventSummaryInfo;
        }
        return this.eventContents;
    }

    public Boolean getAppPayYn() {
        boolean z = false;
        if (this.app_pay_yn != null && !this.app_pay_yn.equals("") && this.app_pay_yn.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            z = true;
        }
        return Boolean.valueOf(z);
    }

    public Boolean getFavoriteYn() {
        return Boolean.valueOf(this.favorite_yn.equals("Y"));
    }

    public String getPayCount() {
        return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(this.pay_cnt)});
    }

    public String getDistance() {
        if (this.distance < 1000) {
            return String.format(Locale.getDefault(), "%,d%s", new Object[]{Integer.valueOf(this.distance), "m"});
        }
        return String.format(Locale.getDefault(), "%,d%s", new Object[]{Integer.valueOf(this.distance / 1000), "km"});
    }

    public String getReviewCnt() {
        return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(this.cnt_review)});
    }

    public String getCallNumber() {
        if (TextUtils.isEmpty(this.tel01)) {
            return "";
        }
        return this.tel01.replaceAll("-", "");
    }

    public String getIntroduce() {
        return "-\n" + this.partner_introduce + "-\n" + this.category_name;
    }

    public String shareMsg() {
        StringBuilder sb = new StringBuilder();
        if (this.partner_introduce.length() > 50) {
            sb.append(this.partner_introduce.substring(0, 50) + "...");
        } else {
            sb.append(this.partner_introduce);
        }
        sb.append("\n\n#\ub108\uc88b\uc73c\ub77c\uace0\ub9cc\ub4e0\uc571 #\uc250\uc5b4\uc573");
        return sb.toString();
    }

    public String getSalesTime() {
        return "\uc815\uc0c1\uc601\uc5c5 : " + this.sales_time + "\n\ud734\ubb34 : " + this.hollyday;
    }

    public String getAddress() {
        return this.road_addr_1 + " " + this.road_addr_2;
    }

    public String getTiker(Context con) {
        return this.couponInfo;
    }

    public String toLink() {
        Map<String, String> map = new HashMap<>();
        map.put("favoriteYn", this.favorite_yn);
        map.put("partnerSno", String.valueOf(this.partner_sno));
        map.put("mapX", String.valueOf(this.map_x));
        map.put("mapY", String.valueOf(this.map_y));
        map.put("partnerName1", this.partner_name1);
        map.put("roadAddr1", this.road_addr_1);
        map.put("mainImgPath", this.img_path);
        return new GsonBuilder().setPrettyPrinting().create().toJson((Object) map);
    }

    public String getRoad_addr_1() {
        return this.road_addr_1;
    }

    public String getRoad_addr_2() {
        return this.road_addr_2;
    }

    public int getPartner_sno() {
        return this.partner_sno;
    }

    public String getParking_type() {
        return this.parking_type;
    }

    public String getShop_way() {
        return this.shop_way;
    }

    public String getService_name() {
        return this.service_name;
    }

    public String getHollyday() {
        return this.hollyday;
    }

    public String getSales_time() {
        return this.sales_time;
    }

    public String getBreak_time() {
        return this.break_time;
    }

    public double getKatec_map_y() {
        return this.katec_map_y;
    }

    public double getKatec_map_x() {
        return this.katec_map_x;
    }

    public int getCnt_view() {
        return this.cnt_view;
    }

    public String getPartner_name1() {
        return this.partner_name1;
    }

    public String getFavorite_yn() {
        return this.favorite_yn;
    }

    public int getCnt_favorite() {
        return this.cnt_favorite;
    }

    public String getLink_url() {
        return this.link_url;
    }

    public String getTraffinc_info() {
        return this.traffinc_info;
    }

    public String getPartner_introduce() {
        return this.partner_introduce;
    }

    public int getCnt_review() {
        return this.cnt_review;
    }

    public int getVogue_cnt() {
        return this.vogue_cnt;
    }

    public int getPay_cnt() {
        return this.pay_cnt;
    }

    public String getImg_path() {
        return this.img_path;
    }

    public String getAddr_1() {
        return this.addr_1;
    }

    public String getTel01() {
        return this.tel01;
    }

    public String getService_type_name() {
        return this.service_type_name;
    }

    public String getTel02() {
        return this.tel02;
    }

    public double getMap_x() {
        return this.map_x;
    }

    public String getHashTag() {
        return this.hash_tag;
    }

    public String getCategory_name() {
        return this.category_name;
    }

    public int getDc_rate() {
        return this.dc_rate;
    }

    public double getMap_y() {
        return this.map_y;
    }

    public String getAddr_2() {
        return this.addr_2;
    }

    public String getParking_yn() {
        return this.parking_yn;
    }

    public String getPartner_name2() {
        return this.partner_name2;
    }

    public String getDongName() {
        return this.dongName;
    }

    public String getApp_pay_yn() {
        return this.app_pay_yn;
    }

    public String getEventRegDate() {
        return this.eventRegDate;
    }

    public String getTermEvent() {
        return this.termEvent;
    }

    public String getEventGubun() {
        return this.eventGubun;
    }

    public String getEventTerm() {
        return this.eventTerm;
    }

    public String getEventContents() {
        return this.eventContents;
    }

    public String getEventSummaryInfo() {
        return this.eventSummaryInfo;
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

    public String getOpenYn() {
        return this.openYn;
    }

    public int getMinute() {
        return 60;
    }

    public int getHour() {
        return 3600;
    }

    public int getDay() {
        return 86400;
    }

    public Boolean getChk_review() {
        return this.chk_review;
    }

    public void setCouponInfo(String couponInfo2) {
        this.couponInfo = couponInfo2;
    }

    public String getCouponInfo() {
        return this.couponInfo;
    }

    public void setListImg(String listImg2) {
        this.listImg = listImg2;
    }

    public String getListImg() {
        return this.listImg;
    }

    public String getDetailContentsImgs() {
        return this.detailContentsImgs;
    }

    public String[] getDetailContentsImgArray() {
        if (this.detailContentsImgs == null || this.detailContentsImgs.isEmpty()) {
            return null;
        }
        return this.detailContentsImgs.split("#DMT#");
    }

    public void setDetailContentsImgs(String detailContentsImgs2) {
        this.detailContentsImgs = detailContentsImgs2;
    }

    public String getUseBizChat() {
        return this.useBizChat;
    }

    public void setUseBizChat(String useBizChat2) {
        this.useBizChat = useBizChat2;
    }

    public String getUseBizChatURL() {
        return this.useBizChatURL;
    }

    public void setUseBizChatURL(String useBizChatURL2) {
        this.useBizChatURL = useBizChatURL2;
    }

    public String getMethod() {
        return this.method;
    }

    public void setMethod(String method2) {
        this.method = method2;
    }
}