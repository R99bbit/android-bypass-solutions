package com.nuvent.shareat.model.store;

import com.facebook.appevents.AppEventsConstants;
import java.util.ArrayList;

public class LocationModel {
    public String areaGroupId;
    public String areaId = "";
    public String areaName = "\ub0b4\uc8fc\ubcc0";
    public String cntArea = AppEventsConstants.EVENT_PARAM_VALUE_NO;
    public Boolean isSelected;
    public String levels;
    public ArrayList<LocationModel> mChildModels;
    public String mapX;
    public String mapY;
    public String ord;
    public String upAreaId;

    public String getMapY() {
        return this.mapY;
    }

    public String getMapX() {
        return this.mapX;
    }

    public String getAreaName() {
        return this.areaName;
    }

    public String getAreaGroupId() {
        return this.areaGroupId;
    }

    public String getCntArea() {
        return this.cntArea;
    }

    public void setCntArea(String cntArea2) {
        this.cntArea = cntArea2;
    }

    public String getLevels() {
        return this.levels;
    }

    public String getOrd() {
        return this.ord;
    }

    public String getAreaId() {
        return this.areaId;
    }

    public String getUpAreaId() {
        return this.upAreaId;
    }

    public Boolean getIsSelected() {
        return this.isSelected;
    }

    public ArrayList<LocationModel> getChildModels() {
        if (this.mChildModels == null) {
            this.mChildModels = new ArrayList<>();
        }
        return this.mChildModels;
    }

    public void setChildModels(ArrayList<LocationModel> mChildModels2) {
        this.mChildModels = mChildModels2;
    }
}