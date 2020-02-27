package com.nuvent.shareat.model;

import java.util.ArrayList;

public class WithdrawInfoModel {
    private ArrayList<String> reason_list = new ArrayList<>();
    private String user_email;
    private String withdraw_guide;

    public String getWithdraw_guide() {
        return this.withdraw_guide;
    }

    public void setWithdraw_guide(String withdraw_guide2) {
        this.withdraw_guide = withdraw_guide2;
    }

    public String getUser_email() {
        return this.user_email;
    }

    public void setUser_email(String user_email2) {
        this.user_email = user_email2;
    }

    public ArrayList<String> getReason_list() {
        return this.reason_list;
    }

    public void setReason_list(ArrayList<String> reason_list2) {
        this.reason_list = reason_list2;
    }
}