package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptSignUp {
    @SerializedName("adid")
    private String adid;
    @SerializedName("agreement1")
    private String agreement1;
    @SerializedName("agreement2")
    private String agreement2;
    @SerializedName("agreement3")
    private String agreement3;
    @SerializedName("agreement4")
    private String agreement4;
    @SerializedName("coachLevel")
    private String coachLevel;
    @SerializedName("dataChannel")
    private String dataChannel;
    @SerializedName("dataSource")
    private String dataSource;
    @SerializedName("dateOfBirth")
    private String dateOfBirth;
    @SerializedName("email")
    private String email;
    @SerializedName("firstName")
    private String firstName;
    @SerializedName("gender")
    private String gender;
    @SerializedName("lastName")
    private String lastName;
    @SerializedName("loginType")
    private String loginType;
    @SerializedName("mobilePhone")
    private String mobilePhone;
    @SerializedName("profileUrl")
    private String profileUrl;
    @SerializedName("quota")
    private String quota;
    @SerializedName("rCode")
    private String rCode;

    public IptSignUp(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, String str15, String str16, String str17, String str18) {
        this.adid = str;
        this.email = str2;
        this.lastName = str3;
        this.firstName = str4;
        this.dateOfBirth = str5;
        this.gender = str6;
        this.mobilePhone = str7;
        this.agreement1 = str8;
        this.agreement2 = str9;
        this.agreement3 = str10;
        this.agreement4 = str11;
        this.quota = str12;
        this.coachLevel = str13;
        this.rCode = str14;
        this.dataSource = str15;
        this.loginType = str16;
        this.profileUrl = str17;
        this.dataChannel = str18;
    }

    public String getAdid() {
        return this.adid;
    }

    public void setAdid(String str) {
        this.adid = str;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String str) {
        this.email = str;
    }

    public String getLastName() {
        return this.lastName;
    }

    public void setLastName(String str) {
        this.lastName = str;
    }

    public String getFirstName() {
        return this.firstName;
    }

    public void setFirstName(String str) {
        this.firstName = str;
    }

    public String getDateOfBirth() {
        return this.dateOfBirth;
    }

    public void setDateOfBirth(String str) {
        this.dateOfBirth = str;
    }

    public String getGender() {
        return this.gender;
    }

    public void setGender(String str) {
        this.gender = str;
    }

    public String getMobilePhone() {
        return this.mobilePhone;
    }

    public void setMobilePhone(String str) {
        this.mobilePhone = str;
    }

    public String getAgreement1() {
        return this.agreement1;
    }

    public void setAgreement1(String str) {
        this.agreement1 = str;
    }

    public String getAgreement2() {
        return this.agreement2;
    }

    public void setAgreement2(String str) {
        this.agreement2 = str;
    }

    public String getAgreement3() {
        return this.agreement3;
    }

    public void setAgreement3(String str) {
        this.agreement3 = str;
    }

    public String getAgreement4() {
        return this.agreement4;
    }

    public void setAgreement4(String str) {
        this.agreement4 = str;
    }

    public String getQuota() {
        return this.quota;
    }

    public void setQuota(String str) {
        this.quota = str;
    }

    public String getCoachLevel() {
        return this.coachLevel;
    }

    public void setCoachLevel(String str) {
        this.coachLevel = str;
    }

    public String getrCode() {
        return this.rCode;
    }

    public void setrCode(String str) {
        this.rCode = str;
    }

    public String getDataSource() {
        return this.dataSource;
    }

    public void setDataSource(String str) {
        this.dataSource = str;
    }

    public String getLoginType() {
        return this.loginType;
    }

    public void setLoginType(String str) {
        this.loginType = str;
    }

    public String getProfileUrl() {
        return this.profileUrl;
    }

    public void setProfileUrl(String str) {
        this.profileUrl = str;
    }

    public String getDataChannel() {
        return this.dataChannel;
    }

    public void setDataChannel(String str) {
        this.dataChannel = str;
    }
}