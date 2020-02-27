package com.nuvent.shareat.model;

public class MyDiscountBenefitModel extends JsonConvertable {
    private String benefitTitleText;
    private String checkListText;
    private String discount;
    private String profile;
    private String result;
    private String result_code;
    private String user_name;

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

    public String getUser_name() {
        return this.user_name;
    }

    public void setUser_name(String user_name2) {
        this.user_name = user_name2;
    }

    public String getBenefitTitleText() {
        return this.benefitTitleText;
    }

    public void setBenefitTitleText(String benefitTitleText2) {
        this.benefitTitleText = benefitTitleText2;
    }

    public String getCheckListText() {
        return this.checkListText;
    }

    public void setCheckListText(String checkListText2) {
        this.checkListText = checkListText2;
    }

    public String getDiscount() {
        return this.discount;
    }

    public void setDiscount(String discount2) {
        this.discount = discount2;
    }

    public String getProfile() {
        return this.profile;
    }

    public void setProfile(String profile2) {
        this.profile = profile2;
    }
}