package co.habitfactory.signalfinance_embrain.callback;

import android.content.Context;
import java.io.Serializable;

public interface SendDataCallBack extends Serializable {
    void dataCallBack(Context context, String str);

    void dataCallBack(String str);
}