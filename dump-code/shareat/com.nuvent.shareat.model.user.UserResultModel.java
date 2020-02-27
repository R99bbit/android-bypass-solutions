package com.nuvent.shareat.model.user;

import com.nuvent.shareat.model.BaseResultModel;

public class UserResultModel extends BaseResultModel {
    private UserModel user_info;

    public UserModel getUserInfo() {
        return this.user_info;
    }

    public void setUserInfo(UserModel user_info2) {
        this.user_info = user_info2;
    }
}