package co.habitfactory.signalfinance_embrain.callback;

import java.io.Serializable;

public interface MissedCheckAlarmCallback extends Serializable {
    void getAlarmCallback(boolean z);
}