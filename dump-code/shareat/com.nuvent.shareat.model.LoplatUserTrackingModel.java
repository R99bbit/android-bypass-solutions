package com.nuvent.shareat.model;

public class LoplatUserTrackingModel extends JsonConvertable {
    private String category_name;
    private String log_type;
    private String partner_name;
    private int partner_sno;
    private String phone_os;
    private String place;
    private String tags;
    private String user_sno;
    private double user_x;
    private double user_y;
    private String version;

    public String getUser_sno() {
        return this.user_sno;
    }

    public void setUser_sno(String userSno) {
        this.user_sno = userSno;
    }

    public String getLog_type() {
        return this.log_type;
    }

    public void setLog_type(String logType) {
        this.log_type = logType;
    }

    public double getUser_x() {
        return this.user_x;
    }

    public void setUser_x(double userX) {
        this.user_x = userX;
    }

    public double getUser_y() {
        return this.user_y;
    }

    public void setUser_y(double userY) {
        this.user_y = userY;
    }

    public String getTags() {
        return this.tags;
    }

    public void setTags(String tags2) {
        this.tags = tags2;
    }

    public String getCategory_name() {
        return this.category_name;
    }

    public void setCategory_name(String categoryName) {
        this.category_name = categoryName;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version2) {
        this.version = version2;
    }

    public String getPhone_os() {
        return this.phone_os;
    }

    public void setPhone_os(String phoneOS) {
        this.phone_os = phoneOS;
    }

    public String getPlace() {
        return this.place;
    }

    public void setPlace(String place2) {
        this.place = place2;
    }

    public int getPartner_sno() {
        return this.partner_sno;
    }

    public void setPartner_sno(int partnerSno) {
        this.partner_sno = partnerSno;
    }

    public String getPartner_name() {
        return this.partner_name;
    }

    public void setPartner_name(String partnerName) {
        this.partner_name = partnerName;
    }
}