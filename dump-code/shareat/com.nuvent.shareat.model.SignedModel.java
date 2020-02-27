package com.nuvent.shareat.model;

import com.nuvent.shareat.model.user.UserModel;

public class SignedModel extends BaseResultModel {
    public String auth_token;
    public UserModel result_session;

    public String getAuth_token() {
        return this.auth_token;
    }

    public void setAuth_token(String auth_token2) {
        this.auth_token = auth_token2;
    }

    public UserModel getResult_session() {
        return this.result_session;
    }

    public void setResult_session(UserModel result_session2) {
        this.result_session = result_session2;
    }
}