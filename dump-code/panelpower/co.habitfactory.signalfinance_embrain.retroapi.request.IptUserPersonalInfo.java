package co.habitfactory.signalfinance_embrain.retroapi.request;

import com.google.gson.annotations.SerializedName;

public class IptUserPersonalInfo extends IptCommon {
    @SerializedName("dateOfBirth")
    private String dateOfBirth;
    @SerializedName("gender")
    private String gender;
    @SerializedName("name")
    private String name;

    public IptUserPersonalInfo(String str, String str2, String str3, String str4) {
        super(str);
        this.name = str2;
        this.gender = str3;
        this.dateOfBirth = str4;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String str) {
        this.name = str;
    }

    public String getGender() {
        return this.gender;
    }

    public void setGender(String str) {
        this.gender = str;
    }

    public String getDateOfBirth() {
        return this.dateOfBirth;
    }

    public void setDateOfBirth(String str) {
        this.dateOfBirth = str;
    }
}