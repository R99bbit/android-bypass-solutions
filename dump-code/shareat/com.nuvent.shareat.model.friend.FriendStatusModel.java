package com.nuvent.shareat.model.friend;

public class FriendStatusModel {
    private String follow_status;
    private String result;
    private String result_code;

    public String getFollow_status() {
        return this.follow_status;
    }

    public String getResult() {
        return this.result;
    }

    public void setResult(String result2) {
        this.result = result2;
    }

    public String getResult_code() {
        return this.result_code;
    }

    public void setResult_code(String result_code2) {
        this.result_code = result_code2;
    }
}