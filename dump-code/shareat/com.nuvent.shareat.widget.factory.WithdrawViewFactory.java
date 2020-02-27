package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.WithdrawReasonModel;

public class WithdrawViewFactory {
    public static View createView(Context context, WithdrawReasonModel model) {
        View convertView = View.inflate(context, R.layout.cell_withdraw, null);
        ((TextView) convertView.findViewById(R.id.titleLabel)).setText(model.getName());
        convertView.findViewById(R.id.titleLabel).setSelected(model.isChecked());
        return convertView;
    }
}