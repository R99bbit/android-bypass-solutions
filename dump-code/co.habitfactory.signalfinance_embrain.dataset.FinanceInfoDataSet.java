package co.habitfactory.signalfinance_embrain.dataset;

public class FinanceInfoDataSet {
    private String financePackageName;
    private String index;

    public FinanceInfoDataSet(String str, String str2) {
        this.index = str;
        this.financePackageName = str2;
    }

    public String getIndex() {
        return this.index;
    }

    public void setIndex(String str) {
        this.index = str;
    }

    public String getFinancePackageName() {
        return this.financePackageName;
    }

    public void setFinancePackageName(String str) {
        this.financePackageName = str;
    }
}