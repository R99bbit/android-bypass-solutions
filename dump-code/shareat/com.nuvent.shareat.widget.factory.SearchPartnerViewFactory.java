package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.ShareAtUtil;
import net.xenix.util.ImageDisplay;

public class SearchPartnerViewFactory {
    public static View createView(Context context, StoreModel model) {
        View convertView = View.inflate(context, R.layout.cell_quick_pay_partner, null);
        String titleName = model.getPartnerName1();
        if (model.getPayYn().equals("Y")) {
            convertView.findViewById(R.id.quickPayStoreIcon).setVisibility(0);
            try {
                if (titleName.length() > 13) {
                    titleName = titleName.substring(0, 13 - "...".length()) + "...";
                }
                ((TextView) convertView.findViewById(R.id.titleLabel)).setText(titleName);
            } catch (Exception e) {
                e.printStackTrace();
                ((TextView) convertView.findViewById(R.id.titleLabel)).setText(titleName);
            }
        } else if (model.getAutoBranchYn().equals("Y")) {
            convertView.findViewById(R.id.autoBranchSelectIcon).setVisibility(0);
            try {
                if (titleName.getBytes("euc-kr").length > 15) {
                    titleName = titleName.substring(0, 15 - "...".length()) + "...";
                }
                ((TextView) convertView.findViewById(R.id.titleLabel)).setText(titleName);
            } catch (Exception e2) {
                e2.printStackTrace();
                ((TextView) convertView.findViewById(R.id.titleLabel)).setText(titleName);
            }
        } else {
            convertView.findViewById(R.id.quickPayStoreIcon).setVisibility(8);
            ((TextView) convertView.findViewById(R.id.titleLabel)).setText(titleName);
        }
        try {
            ((TextView) convertView.findViewById(R.id.locationLabel)).setText(model.getDongName() + " " + ShareAtUtil.getDistanceMark(model.getDistance()));
        } catch (Exception e3) {
            e3.printStackTrace();
            ((TextView) convertView.findViewById(R.id.locationLabel)).setText(model.getDongName() + " " + model.getDistance() + "m");
        }
        ((TextView) convertView.findViewById(R.id.categoryLabel)).setText(model.getCategoryName());
        ImageView coverImageView = (ImageView) convertView.findViewById(R.id.coverImageView);
        if (model.getIconPath() != null && !model.getIconPath().isEmpty()) {
            ImageDisplay.getInstance().displayImageLoadRound(model.getIconPath(), coverImageView, context.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX), (int) R.drawable.interest_img_field);
        } else if (model.getListImg() != null && !model.getListImg().isEmpty()) {
            ImageDisplay.getInstance().displayImageLoadRound(model.getListImg(), coverImageView, context.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX), (int) R.drawable.interest_img_field);
        }
        return convertView;
    }
}