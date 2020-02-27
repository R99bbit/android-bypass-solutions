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
import com.nuvent.shareat.model.user.CardModel;
import java.util.List;

public class PayTypePickerPopup extends DialogFragment implements OnClickListener {
    public static final String TAG = PayTypePickerPopup.class.getSimpleName();
    private PayTypePickerCallback callback;
    private List<CardModel> mList;

    public interface PayTypePickerCallback {
        void onPayTypePicker(CardModel cardModel, Boolean bool);
    }

    public static PayTypePickerPopup newInstance(PayTypePickerCallback callback2, List<CardModel> list) {
        PayTypePickerPopup d = new PayTypePickerPopup();
        d.callback = callback2;
        d.mList = list;
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
        Context context = getActivity().getApplicationContext();
        LayoutInflater inflater = LayoutInflater.from(context);
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(1);
        View item = inflater.inflate(R.layout.view_pay_type, layout, false);
        layout.addView(item);
        ((TextView) item.findViewById(R.id.name)).setText(getString(R.string.pay_type_all));
        item.setOnClickListener(this);
        for (CardModel card : this.mList) {
            View item2 = inflater.inflate(R.layout.view_pay_type, layout, false);
            layout.addView(item2);
            ((TextView) item2.findViewById(R.id.name)).setText(card.getCard_name());
            item2.setTag(card);
            item2.setOnClickListener(this);
        }
        getDialog().setContentView(layout);
    }

    public void onClick(View v) {
        if (this.callback != null) {
            Object card = v.getTag();
            this.callback.onPayTypePicker(card == null ? null : (CardModel) card, Boolean.valueOf(true));
        }
        dismiss();
    }
}