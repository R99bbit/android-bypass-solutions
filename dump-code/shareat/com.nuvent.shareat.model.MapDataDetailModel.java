package com.nuvent.shareat.model;

public class MapDataDetailModel extends BaseResultModel {
    String categoryName;
    String couponGroupSno;
    String couponName;
    String couponType;
    String couponTypeText;
    int dcRate;
    String discountValue;
    String distance;
    String dongName;
    String eventType;
    String imgPath;
    String mapX;
    String mapY;
    String menuList;
    String partnerName1;
    String partnerSno;
    String payMethod;
    String pickTextType;
    String pinText;
    String readAddr;
    String rowNum;
    String tel01;

    public String getPinText() {
        return this.pinText;
    }

    public void setPinText(String pinText2) {
        this.pinText = pinText2;
    }

    public boolean getPayMethod() {
        return this.payMethod.equals("APP");
    }

    public void setPayMethod(String payMethod2) {
        this.payMethod = payMethod2;
    }

    public String getCouponName() {
        return this.couponName;
    }

    public void setCouponName(String couponName2) {
        this.couponName = couponName2;
    }

    public String getCouponGroupSno() {
        return this.couponGroupSno;
    }

    public void setCouponGroupSno(String couponGroupSno2) {
        this.couponGroupSno = couponGroupSno2;
    }

    public String getDongName() {
        return this.dongName == null ? "" : this.dongName;
    }

    public void setDongName(String dongName2) {
        this.dongName = dongName2;
    }

    public String getTel01() {
        return this.tel01 == null ? "" : this.tel01;
    }

    public void setTel01(String tel012) {
        this.tel01 = tel012;
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
        return this.partnerName1 == null ? "" : this.partnerName1;
    }

    public void setPartnerName1(String partnerName12) {
        this.partnerName1 = partnerName12;
    }

    public String getDistance() {
        return this.distance == null ? "" : this.distance;
    }

    public void setDistance(String distance2) {
        this.distance = distance2;
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

    public String getReadAddr() {
        return this.readAddr;
    }

    public void setReadAddr(String readAddr2) {
        this.readAddr = readAddr2;
    }

    public String getImgPath() {
        return this.imgPath;
    }

    public void setImgPath(String imgPath2) {
        this.imgPath = imgPath2;
    }

    public String getCategoryName() {
        return this.categoryName == null ? "" : this.categoryName;
    }

    public void setCategoryName(String categoryName2) {
        this.categoryName = categoryName2;
    }

    public String getEventType() {
        return this.eventType;
    }

    public void setEventType(String eventType2) {
        this.eventType = eventType2;
    }

    public String getPickTextType() {
        return this.pickTextType;
    }

    public void setPickTextType(String pickTextType2) {
        this.pickTextType = pickTextType2;
    }

    public String getMenuList() {
        return this.menuList == null ? "" : this.menuList;
    }

    public void setMenuList(String menuList2) {
        this.menuList = menuList2;
    }

    public int getDcRate() {
        return this.dcRate;
    }

    public void setDcRate(int dcRate2) {
        this.dcRate = dcRate2;
    }

    public String getCouponType() {
        return this.couponType;
    }

    public void setCouponType(String couponType2) {
        this.couponType = couponType2;
    }

    public String getCouponTypeText() {
        return this.couponTypeText == null ? "" : this.couponTypeText;
    }

    public void setCouponTypeText(String couponTypeText2) {
        this.couponTypeText = couponTypeText2;
    }

    public String getDiscountValue() {
        return this.discountValue == null ? "" : this.discountValue;
    }

    public void setDiscountValue(String discountValue2) {
        this.discountValue = discountValue2;
    }
}