package co.habitfactory.signalfinance_embrain.callback;

import co.habitfactory.signalfinance_embrain.dataset.SmsDataSet;
import java.io.Serializable;
import java.util.ArrayList;

public interface GetMessageCallback extends Serializable {
    void getMsgCallback(ArrayList<SmsDataSet> arrayList);
}