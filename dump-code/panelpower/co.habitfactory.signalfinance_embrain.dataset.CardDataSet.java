package co.habitfactory.signalfinance_embrain.dataset;

public class CardDataSet {
    private String cardCompanyName;
    private String cardId;
    private String cardQuato;

    public CardDataSet(String str, String str2, String str3) {
        this.cardId = str;
        this.cardCompanyName = str2;
        this.cardQuato = str3;
    }

    public String getCardId() {
        return this.cardId;
    }

    public void setCardId(String str) {
        this.cardId = str;
    }

    public String getCardCompanyName() {
        return this.cardCompanyName;
    }

    public void setCardCompanyName(String str) {
        this.cardCompanyName = str;
    }

    public String getCardQuato() {
        return this.cardQuato;
    }

    public void setCardQuato(String str) {
        this.cardQuato = str;
    }
}