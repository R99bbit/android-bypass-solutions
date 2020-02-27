package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.FaqTypeModel;

public class FaqTypeViewFactory {
    public static View createView(Context context, FaqTypeModel model) {
        View convertView = View.inflate(context, R.layout.cell_dialog_faq, null);
        ((TextView) convertView.findViewById(R.id.typeLabel)).setText(model.getCode_name());
        return convertView;
    }
}