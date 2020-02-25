package co.habitfactory.signalfinance_embrain.dataset;

public class ParseDataSimpleSet {
    private boolean boolNeedPopup;
    private String gpsStatus;
    private String isFrom;
    private String smsId;

    public ParseDataSimpleSet(String str, String str2, String str3, boolean z) {
        this.smsId = str;
        this.gpsStatus = str2;
        this.isFrom = str3;
        this.boolNeedPopup = z;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getGpsStatus() {
        return this.gpsStatus;
    }

    public void setGpsStatus(String str) {
        this.gpsStatus = str;
    }

    public String getIsFrom() {
        return this.isFrom;
    }

    public void setIsFrom(String str) {
        this.isFrom = str;
    }

    public boolean isBoolNeedPopup() {
        return this.boolNeedPopup;
    }

    public void setBoolNeedPopup(boolean z) {
        this.boolNeedPopup = z;
    }
}