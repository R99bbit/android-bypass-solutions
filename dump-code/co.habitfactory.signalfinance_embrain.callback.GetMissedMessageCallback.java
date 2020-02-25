package co.habitfactory.signalfinance_embrain.callback;

import co.habitfactory.signalfinance_embrain.dataset.SmsDataSet;
import java.io.Serializable;
import java.util.ArrayList;

public interface GetMissedMessageCallback extends Serializable {
    void getMissedMsgCallback(ArrayList<SmsDataSet> arrayList);
}