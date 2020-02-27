package com.nuvent.shareat.model.store;

import android.support.graphics.drawable.PathInterpolatorCompat;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.fragment.StoreDetailFragment;
import com.nuvent.shareat.model.JsonConvertable;

public class StoreParamsModel extends JsonConvertable {
    public static final int CHECK = 2;
    public static final int DISTANCE = 1;
    public static final int EVENT = 0;
    public static final int FAVORITE = 3;
    public static final int FRIEND = 4;
    public static final int LIKE_CNT = 5;
    public static final int PAY_COUNT = 7;
    public static final int REVIEW = 6;
    public final String[] LIST_TYPE = {"event", "distance", "check", "favorite", "friend", "like_cnt", StoreDetailFragment.SUB_TAB_NAME_REVIEW, "cnt_pay", "pay_date"};
    public final String ORDER_ASC = "ASC";
    public final String ORDER_DESC = "DESC";
    public String areaName = "";
    public int cnt = 10;
    public Boolean isSearch = Boolean.valueOf(false);
    public int lType = 0;
    private int limitDistance = PathInterpolatorCompat.MAX_NUM_POINTS;
    public String order_Type = "ASC";
    public int page = 1;
    public String searchAreaId = "";
    public String searchCategoryId = "";
    public String searchName = "";
    public int status;
    public String userX = "";
    public String userY = "";
    public int viewCount = 10;

    public int getViewCount() {
        return this.viewCount;
    }

    public void setViewCount(int count) {
        this.viewCount = count;
    }

    public int getLimitDistance() {
        return this.limitDistance;
    }

    public void setLimitDistance(int limitDistance2) {
        this.limitDistance = limitDistance2;
    }

    public String getStringConvertPage() {
        return String.valueOf(this.page);
    }

    public String getStringConvertCnt() {
        return String.valueOf(this.cnt);
    }

    public String getUserX() {
        if (this.userX == null || this.userX.equals("") || this.userX.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            this.userX = "127.0270210";
        }
        return this.userX;
    }

    public String getUserY() {
        if (this.userY.equals("") || this.userY == null || this.userY.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            this.userY = "37.4986366";
        }
        return this.userY;
    }

    public Boolean getIsSearch() {
        return this.isSearch;
    }

    public void setIsSearch(Boolean isSearch2) {
        this.isSearch = isSearch2;
    }

    public String getOrder_Type() {
        return this.order_Type;
    }

    public void setOrder_Type(String order_Type2) {
        this.order_Type = order_Type2;
    }

    public int getPage() {
        return this.page;
    }

    public void setPage(int page2) {
        this.page = page2;
    }

    public String getListType(int type) {
        return this.LIST_TYPE[type];
    }

    public void setListType(String value) {
        for (int i = 0; i < this.LIST_TYPE.length; i++) {
            if (this.LIST_TYPE[i].equals(value)) {
                setlType(i);
                return;
            }
        }
    }

    public int getlType() {
        return this.lType;
    }

    public void setlType(int lType2) {
        this.lType = lType2;
    }

    public void setUserX(String userX2) {
        this.userX = userX2;
    }

    public void setUserY(String userY2) {
        this.userY = userY2;
    }

    public String getSearchName() {
        return this.searchName;
    }

    public void setSearchName(String searchName2) {
        this.searchName = searchName2;
    }

    public String getSearchCategoryId() {
        return this.searchCategoryId;
    }

    public void setSearchCategoryId(String searchCategoryId2) {
        this.searchCategoryId = searchCategoryId2;
    }

    public String getSearchAreaId() {
        return this.searchAreaId;
    }

    public void setSearchAreaId(String searchAreaId2) {
        this.searchAreaId = searchAreaId2;
    }

    public String getAreaName() {
        return this.areaName == null ? "" : this.areaName;
    }

    public void setAreaName(String areaName2) {
        this.areaName = areaName2;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status2) {
        this.status = status2;
    }

    public int getCnt() {
        return this.cnt;
    }

    public void setCnt(int cnt2) {
        this.cnt = cnt2;
    }
}