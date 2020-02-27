package com.nuvent.shareat.model.store;

import android.text.TextUtils;
import com.igaworks.interfaces.CommonInterface;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class ProfileStoreModel {
    private String addr1;
    private String addr2;
    private String appPayYn;
    private String areaName;
    private String categoryId;
    private String categoryImg;
    private String categoryName;
    private String dcRate;
    private String distance;
    private String dongName;
    private String eventRegDate;
    private String favoriteYn;
    private String img_save_url;
    private String img_thumbnail_url;
    private String img_url;
    private String katecMapX;
    private String katecMapY;
    private String likeCnt;
    private String linkUrl;
    private String listImg;
    private String mainImgPath;
    private String mapX;
    private String mapY;
    private String partnerIntroduce;
    private String partnerName1;
    private String partnerName2;
    private String partnerSno;
    private String payCnt;
    private String roadAddr1;
    private String roadAddr2;
    private String rowNum;
    private String tel01;
    private String tel02;
    private float termEvent;
    private String vogueCnt;

    public String getImg_url() {
        return this.img_url;
    }

    public void setImg_url(String img_url2) {
        this.img_url = img_url2;
    }

    public String getImg_save_url() {
        return this.img_save_url;
    }

    public void setImg_save_url(String img_save_url2) {
        this.img_save_url = img_save_url2;
    }

    public String getImg_thumbnail_url() {
        return this.img_thumbnail_url;
    }

    public void setImg_thumbnail_url(String img_thumbnail_url2) {
        this.img_thumbnail_url = img_thumbnail_url2;
    }

    public String getMainImgPath() {
        return this.mainImgPath;
    }

    public void setMainImgPath(String mainImgPath2) {
        this.mainImgPath = mainImgPath2;
    }

    public String getRowNum() {
        return this.rowNum;
    }

    public void setRowNum(String rowNum2) {
        this.rowNum = rowNum2;
    }

    public String getPartnerSno() {
        return this.partnerSno;
    }

    public void setPartnerSno(String partnerSno2) {
        this.partnerSno = partnerSno2;
    }

    public String getPartnerName1() {
        return this.partnerName1;
    }

    public void setPartnerName1(String partnerName12) {
        this.partnerName1 = partnerName12;
    }

    public String getTel01() {
        return this.tel01;
    }

    public void setTel01(String tel012) {
        this.tel01 = tel012;
    }

    public String getAddr1() {
        return this.addr1;
    }

    public void setAddr1(String addr12) {
        this.addr1 = addr12;
    }

    public String getAddr2() {
        return this.addr2;
    }

    public void setAddr2(String addr22) {
        this.addr2 = addr22;
    }

    public String getMapX() {
        return this.mapX;
    }

    public void setMapX(String mapX2) {
        this.mapX = mapX2;
    }

    public String getMapY() {
        return this.mapY;
    }

    public void setMapY(String mapY2) {
        this.mapY = mapY2;
    }

    public String getCategoryId() {
        return this.categoryId;
    }

    public void setCategoryId(String categoryId2) {
        this.categoryId = categoryId2;
    }

    public String getCategoryName() {
        return this.categoryName;
    }

    public void setCategoryName(String categoryName2) {
        this.categoryName = categoryName2;
    }

    public String getCategoryImg() {
        return this.categoryImg;
    }

    public void setCategoryImg(String categoryImg2) {
        this.categoryImg = categoryImg2;
    }

    public String getAreaName() {
        return this.areaName;
    }

    public void setAreaName(String areaName2) {
        this.areaName = areaName2;
    }

    public String getDongName() {
        return this.dongName;
    }

    public void setDongName(String dongName2) {
        this.dongName = dongName2;
    }

    public String getListImg() {
        return this.listImg;
    }

    public void setListImg(String listImg2) {
        this.listImg = listImg2;
    }

    public String getDcRate() {
        return this.dcRate;
    }

    public void setDcRate(String dcRate2) {
        this.dcRate = dcRate2;
    }

    public void setDistance(String distance2) {
        this.distance = distance2;
    }

    public String getFavoriteYn() {
        return this.favoriteYn;
    }

    public void setFavoriteYn(String favoriteYn2) {
        this.favoriteYn = favoriteYn2;
    }

    public String getPayCnt() {
        return this.payCnt;
    }

    public void setPayCnt(String payCnt2) {
        this.payCnt = payCnt2;
    }

    public String getLikeCnt() {
        return this.likeCnt;
    }

    public void setLikeCnt(String likeCnt2) {
        this.likeCnt = likeCnt2;
    }

    public String getVogueCnt() {
        return this.vogueCnt;
    }

    public void setVogueCnt(String vogueCnt2) {
        this.vogueCnt = vogueCnt2;
    }

    public String getEventRegDate() {
        return this.eventRegDate;
    }

    public void setEventRegDate(String eventRegDate2) {
        this.eventRegDate = eventRegDate2;
    }

    public float getTermEvent() {
        return this.termEvent;
    }

    public void setTermEvent(float termEvent2) {
        this.termEvent = termEvent2;
    }

    public String getAppPayYn() {
        return this.appPayYn;
    }

    public void setAppPayYn(String appPayYn2) {
        this.appPayYn = appPayYn2;
    }

    public String getTel02() {
        return this.tel02;
    }

    public void setTel02(String tel022) {
        this.tel02 = tel022;
    }

    public String getPartnerName2() {
        return this.partnerName2;
    }

    public void setPartnerName2(String partnerName22) {
        this.partnerName2 = partnerName22;
    }

    public String getPartnerIntroduce() {
        return this.partnerIntroduce;
    }

    public void setPartnerIntroduce(String partnerIntroduce2) {
        this.partnerIntroduce = partnerIntroduce2;
    }

    public String getRoadAddr1() {
        return this.roadAddr1;
    }

    public void setRoadAddr1(String roadAddr12) {
        this.roadAddr1 = roadAddr12;
    }

    public String getRoadAddr2() {
        return this.roadAddr2;
    }

    public void setRoadAddr2(String roadAddr22) {
        this.roadAddr2 = roadAddr22;
    }

    public String getKatecMapX() {
        return this.katecMapX;
    }

    public void setKatecMapX(String katecMapX2) {
        this.katecMapX = katecMapX2;
    }

    public String getKatecMapY() {
        return this.katecMapY;
    }

    public void setKatecMapY(String katecMapY2) {
        this.katecMapY = katecMapY2;
    }

    public String getLinkUrl() {
        return this.linkUrl;
    }

    public void setLinkUrl(String linkUrl2) {
        this.linkUrl = linkUrl2;
    }

    public String getDateText() {
        String term = getTerm();
        return TextUtils.isEmpty(term) ? getDate() : term;
    }

    public String getDate() {
        if (TextUtils.isEmpty(this.eventRegDate)) {
            return "";
        }
        SimpleDateFormat format = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.getDefault());
        try {
            Date date = format.parse(this.eventRegDate);
            format.applyPattern("yyyy-MM-dd");
            return format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
            return this.eventRegDate;
        }
    }

    public String getTerm() {
        if (TextUtils.isEmpty(String.valueOf(this.termEvent))) {
            return "";
        }
        try {
            int value = (int) this.termEvent;
            if (value == 0 || value > 1440) {
                return "";
            }
            if (value < 60) {
                return value + "\ubd84 \uc804";
            }
            return (value / 60) + "\uc2dc\uac04 \uc804";
        } catch (NumberFormatException e) {
            return "";
        }
    }

    public String getStoreAddrDist() {
        StringBuilder sb = new StringBuilder();
        if (!TextUtils.isEmpty(this.dongName)) {
            sb.append(this.dongName);
        }
        if (!TextUtils.isEmpty(this.distance)) {
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(getDistance());
        }
        return sb.toString();
    }

    public String getDistance() {
        if (!TextUtils.isEmpty(this.distance)) {
            try {
                int value = Integer.valueOf(this.distance).intValue();
                if (value == 0) {
                    return "";
                }
                if (value < 1000) {
                    return String.format(Locale.getDefault(), "%,d%s", new Object[]{Integer.valueOf(value), "m"});
                }
                return String.format(Locale.getDefault(), "%,d%s", new Object[]{Integer.valueOf(value / 1000), "Km"});
            } catch (NumberFormatException e) {
            }
        }
        return "";
    }
}