package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build.VERSION;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.StoreModel;
import net.xenix.android.widget.LetterSpacingTextView;
import net.xenix.util.ImageDisplay;

public class StoreViewFactory {
    public static View createView(Context context, StoreModel model, Typeface typeface) {
        int i;
        int i2 = 0;
        View convertView = View.inflate(context, R.layout.cell_store, null);
        ((LetterSpacingTextView) convertView.findViewById(R.id.storeNameLabel)).setCustomLetterSpacing(-1.3f);
        ((LetterSpacingTextView) convertView.findViewById(R.id.reviewLabel)).setCustomLetterSpacing(-1.3f);
        ((LetterSpacingTextView) convertView.findViewById(R.id.dcLabel)).setCustomLetterSpacing(-1.3f);
        ImageDisplay.getInstance().displayImageLoad(model.getMainImgUrl(), (ImageView) convertView.findViewById(R.id.storeImageView), (int) R.drawable.main_shop_photo);
        ((TextView) convertView.findViewById(R.id.timeLabel)).setText(model.getTermEvent()[0]);
        ((TextView) convertView.findViewById(R.id.timeFormatLabel)).setText(model.getTermEvent()[1]);
        TextView textView = (TextView) convertView.findViewById(R.id.topMessageLabel);
        ((TextView) convertView.findViewById(R.id.dcLabel)).setText(model.getCouponInfo());
        ((TextView) convertView.findViewById(R.id.storeNameLabel)).setText(model.getPartnerName1());
        ((TextView) convertView.findViewById(R.id.categoryLabel)).setText(model.getCategoryName());
        ((TextView) convertView.findViewById(R.id.locationLabel)).setText(model.getDongName() + " " + model.getDistanceMark());
        convertView.findViewById(R.id.reviewCount).setVisibility(model.getAppPayYn() ? 0 : 8);
        View findViewById = convertView.findViewById(R.id.ballonIcon);
        if (model.getAppPayYn()) {
            i = 0;
        } else {
            i = 8;
        }
        findViewById.setVisibility(i);
        ((TextView) convertView.findViewById(R.id.reviewCount)).setText(model.getReviewCount());
        if (VERSION.SDK_INT >= 16) {
            ((ImageView) convertView.findViewById(R.id.ballonIcon)).setBackground(context.getResources().getDrawable(R.drawable.main_ballon_b));
        } else {
            ((ImageView) convertView.findViewById(R.id.ballonIcon)).setBackgroundDrawable(context.getResources().getDrawable(R.drawable.main_ballon_b));
        }
        ((TextView) convertView.findViewById(R.id.reviewLabel)).setText((model.getEventContents() == null || model.getEventContents().equals("")) ? context.getResources().getString(R.string.STORE_NEW_REGIST) : model.getEventContents().trim());
        if (model.getCouponGroupSno() == null || model.getCouponGroupSno().equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            convertView.findViewById(R.id.couponLabelLayout).setVisibility(8);
        } else {
            convertView.findViewById(R.id.couponLabelLayout).setVisibility(0);
            ((TextView) convertView.findViewById(R.id.couponNameLabel)).setText(model.getCouponName());
        }
        if (model.isBarcode()) {
            convertView.findViewById(R.id.barcodeStoreLabel).setVisibility(0);
        } else {
            convertView.findViewById(R.id.barcodeStoreLabel).setVisibility(8);
        }
        if (model.isPayView()) {
            ((ImageView) convertView.findViewById(R.id.payIconView)).setImageResource(R.drawable.icon_store_pay_count);
            ((TextView) convertView.findViewById(R.id.payCountLabel)).setText(model.getRecentPayCount());
            ((TextView) convertView.findViewById(R.id.payLabel)).setText("\uba85 \uacb0\uc81c");
            ((TextView) convertView.findViewById(R.id.payLabel)).setTextColor(Color.parseColor("#ff6385e6"));
            View findViewById2 = convertView.findViewById(R.id.timeLayout);
            if (model.isFirstStore().booleanValue()) {
                i2 = 4;
            }
            findViewById2.setVisibility(i2);
        } else {
            ((ImageView) convertView.findViewById(R.id.payIconView)).setImageResource(R.drawable.icon_store_pay_count_d);
            ((TextView) convertView.findViewById(R.id.payCountLabel)).setText("");
            ((TextView) convertView.findViewById(R.id.payLabel)).setText("\uacb0\uc81c\ubbf8\uc218\uc2e0 \ub9e4\uc7a5");
            ((TextView) convertView.findViewById(R.id.payLabel)).setTextColor(Color.parseColor("#4c6385e6"));
            convertView.findViewById(R.id.timeLayout).setVisibility(8);
        }
        if (model.isEventPartner()) {
            ((TextView) convertView.findViewById(R.id.dcLabel)).setText(model.getAdditionalDesc());
        }
        return convertView;
    }
}