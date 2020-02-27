package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.CouponDetailModel;
import net.xenix.util.FormatUtil;

public class CouponViewFactory {
    public static View createView(Context context, CouponDetailModel model) {
        String couponValue;
        View convertView = View.inflate(context, R.layout.cell_dialog_coupon, null);
        ((ImageView) convertView.findViewById(R.id.checkButton)).setImageResource(model.isChecked() ? R.drawable.abc_btn_radio_to_on_mtrl_015 : R.drawable.abc_btn_radio_to_on_mtrl_000);
        if (model.getCoupon_type().equals("10")) {
            couponValue = FormatUtil.onDecimalFormat(model.getDiscount_value()) + "\uc6d0 \ud560\uc778";
        } else {
            couponValue = model.getDiscount_value() + "% \ud560\uc778";
        }
        ((TextView) convertView.findViewById(R.id.nameLabel)).setText(couponValue + "(" + FormatUtil.onDecimalFormat(model.getMin_condition()) + "\uc6d0\uc774\uc0c1\uacb0\uc81c\uc2dc)");
        ((TextView) convertView.findViewById(R.id.titleLabel)).setText(model.getCoupon_name());
        ((TextView) convertView.findViewById(R.id.dateLabel)).setText("\uc720\ud6a8\uae30\uac04 : ~ " + model.getExpire_date() + "\uae4c\uc9c0");
        ((TextView) convertView.findViewById(R.id.usePlaceLabel)).setText("\uc0ac\uc6a9\ucc98 : " + model.getUsable_partner_name());
        return convertView;
    }
}