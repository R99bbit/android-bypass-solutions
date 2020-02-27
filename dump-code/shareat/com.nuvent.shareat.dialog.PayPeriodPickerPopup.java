package com.nuvent.shareat.dialog;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;

public class PayPeriodPickerPopup extends DialogFragment implements OnClickListener {
    public static final String TAG = PayPeriodPickerPopup.class.getSimpleName();
    private String[] arrPeriod;
    private PayPeriodPickerCallback callback;

    public interface PayPeriodPickerCallback {
        void onPayPeriodPicker(String str, int i, int i2);
    }

    public static PayPeriodPickerPopup newInstance(PayPeriodPickerCallback callback2) {
        PayPeriodPickerPopup d = new PayPeriodPickerPopup();
        d.callback = callback2;
        return d;
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(1, R.style.AppDialogTheme);
    }

    public Dialog onCreateDialog(Bundle savedInstanceState) {
        return new Dialog(getActivity());
    }

    public void onActivityCreated(Bundle arg0) {
        super.onActivityCreated(arg0);
        initDialog();
    }

    private void initDialog() {
        String[] strArr;
        Context context = getActivity().getApplicationContext();
        LayoutInflater inflater = LayoutInflater.from(context);
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(1);
        this.arrPeriod = getResources().getStringArray(R.array.pay_period);
        for (String period : this.arrPeriod) {
            View item = inflater.inflate(R.layout.view_pay_type, layout, false);
            layout.addView(item);
            ((TextView) item.findViewById(R.id.name)).setText(period);
            item.setTag(period);
            item.setOnClickListener(this);
        }
        getDialog().setContentView(layout);
    }

    public void onClick(View v) {
        if (this.callback != null) {
            String period = (String) v.getTag();
            if (period.equals(this.arrPeriod[0])) {
                this.callback.onPayPeriodPicker(period, 5, 0);
            } else if (period.equals(this.arrPeriod[1])) {
                this.callback.onPayPeriodPicker(period, 4, -1);
            } else if (period.equals(this.arrPeriod[2])) {
                this.callback.onPayPeriodPicker(period, 2, -1);
            } else if (period.equals(this.arrPeriod[3])) {
                this.callback.onPayPeriodPicker(period, 2, -3);
            }
        }
        dismiss();
    }
}