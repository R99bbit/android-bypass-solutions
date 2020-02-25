package co.habitfactory.signalfinance_embrain.retroapi.response.layout.member;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;

public class OptLogIn extends OptResultDataset {
    @SerializedName("adid")
    private String adid;
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
    @SerializedName("mobilePhone")
    private String mobilePhone;
    @SerializedName("recCode")
    private String recCode;
    @SerializedName("userId")
    private String userId;

    public OptLogIn(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11) {
        super(str, str2);
        this.userId = str3;
        this.lastName = str4;
        this.firstName = str5;
        this.email = str6;
        this.dateOfBirth = str7;
        this.gender = str8;
        this.adid = str9;
        this.mobilePhone = str10;
        this.recCode = str11;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String str) {
        this.userId = str;
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

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String str) {
        this.email = str;
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

    public String getAdid() {
        return this.adid;
    }

    public void setAdid(String str) {
        this.adid = str;
    }

    public String getMobilePhone() {
        return this.mobilePhone;
    }

    public void setMobilePhone(String str) {
        this.mobilePhone = str;
    }

    public String getRecCode() {
        return this.recCode;
    }

    public void setRecCode(String str) {
        this.recCode = str;
    }
}