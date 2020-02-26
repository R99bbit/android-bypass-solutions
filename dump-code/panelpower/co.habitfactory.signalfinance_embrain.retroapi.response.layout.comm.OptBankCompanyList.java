package co.habitfactory.signalfinance_embrain.retroapi.response.layout.comm;

import co.habitfactory.signalfinance_embrain.retroapi.response.OptResultDataset;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;

public class OptBankCompanyList extends OptResultDataset {
    @SerializedName("bankList")
    private ArrayList<BankCompany> bankList;

    public OptBankCompanyList(String str, String str2, ArrayList<BankCompany> arrayList) {
        super(str, str2);
        this.bankList = arrayList;
    }

    public ArrayList<BankCompany> getBankList() {
        return this.bankList;
    }

    public void setBankList(ArrayList<BankCompany> arrayList) {
        this.bankList = arrayList;
    }
}