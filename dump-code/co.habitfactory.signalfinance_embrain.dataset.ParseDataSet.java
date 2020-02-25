package co.habitfactory.signalfinance_embrain.dataset;

public class ParseDataSet {
    private boolean boolNeedPopup;
    private String cancelCode;
    private String categoryCode;
    private String categoryImage;
    private String categoryName;
    private String currencyUnit;
    private String dailyLimit;
    private String dailySum;
    private String gpsStatus;
    private String isFrom;
    private String rating;
    private String smsId;
    private String spendPrice;
    private String sum;
    private String usedPlace;

    public ParseDataSet(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, boolean z) {
        this.categoryCode = str;
        this.categoryName = str2;
        this.categoryImage = str3;
        this.dailyLimit = str4;
        this.dailySum = str5;
        this.sum = str6;
        this.smsId = str7;
        this.usedPlace = str8;
        this.spendPrice = str9;
        this.currencyUnit = str10;
        this.gpsStatus = str11;
        this.rating = str12;
        this.cancelCode = str13;
        this.isFrom = str14;
        this.boolNeedPopup = z;
    }

    public String getCategoryCode() {
        return this.categoryCode;
    }

    public void setCategoryCode(String str) {
        this.categoryCode = str;
    }

    public String getCategoryName() {
        return this.categoryName;
    }

    public void setCategoryName(String str) {
        this.categoryName = str;
    }

    public String getCategoryImage() {
        return this.categoryImage;
    }

    public void setCategoryImage(String str) {
        this.categoryImage = str;
    }

    public String getDailyLimit() {
        return this.dailyLimit;
    }

    public void setDailyLimit(String str) {
        this.dailyLimit = str;
    }

    public String getDailySum() {
        return this.dailySum;
    }

    public void setDailySum(String str) {
        this.dailySum = str;
    }

    public String getSum() {
        return this.sum;
    }

    public void setSum(String str) {
        this.sum = str;
    }

    public String getSmsId() {
        return this.smsId;
    }

    public void setSmsId(String str) {
        this.smsId = str;
    }

    public String getUsedPlace() {
        return this.usedPlace;
    }

    public void setUsedPlace(String str) {
        this.usedPlace = str;
    }

    public String getSpendPrice() {
        return this.spendPrice;
    }

    public void setSpendPrice(String str) {
        this.spendPrice = str;
    }

    public String getCurrencyUnit() {
        return this.currencyUnit;
    }

    public void setCurrencyUnit(String str) {
        this.currencyUnit = str;
    }

    public String getGpsStatus() {
        return this.gpsStatus;
    }

    public void setGpsStatus(String str) {
        this.gpsStatus = str;
    }

    public String getRating() {
        return this.rating;
    }

    public void setRating(String str) {
        this.rating = str;
    }

    public String getCancelCode() {
        return this.cancelCode;
    }

    public void setCancelCode(String str) {
        this.cancelCode = str;
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