package co.habitfactory.signalfinance_embrain.dataset;

public class SmsReceiveNumberSet {
    private String receiveNumber;
    private String receiveNumberName;
    private String receiveNumberType;

    public SmsReceiveNumberSet(String str, String str2, String str3) {
        this.receiveNumber = str;
        this.receiveNumberName = str2;
        this.receiveNumberType = str3;
    }

    public String getReceiveNumber() {
        return this.receiveNumber;
    }

    public void setReceiveNumber(String str) {
        this.receiveNumber = str;
    }

    public String getReceiveNumberName() {
        return this.receiveNumberName;
    }

    public void setReceiveNumberName(String str) {
        this.receiveNumberName = str;
    }

    public String getReceiveNumberType() {
        return this.receiveNumberType;
    }

    public void setReceiveNumberType(String str) {
        this.receiveNumberType = str;
    }
}