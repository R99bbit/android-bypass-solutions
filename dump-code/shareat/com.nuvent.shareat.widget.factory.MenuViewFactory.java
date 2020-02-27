package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.StoreMenuModel;

public class MenuViewFactory {
    public static View createView(Context context, StoreMenuModel model, String type) {
        View convertView = View.inflate(context, R.layout.cell_menu, null);
        ((TextView) convertView.findViewById(R.id.menuNameLabel)).setText(model.getMenu_name());
        ((TextView) convertView.findViewById(R.id.menuPriceLabel)).setText(model.getPrice());
        if (!type.equals("ES")) {
            convertView.findViewById(R.id.rankIconLayout).setVisibility(8);
            convertView.findViewById(R.id.menuRankLabel).setVisibility(8);
        } else {
            if (model.getMenu_rank() == null || model.getMenu_rank().equals(AppEventsConstants.EVENT_PARAM_VALUE_NO) || model.getMenu_rank().equals("-")) {
                convertView.findViewById(R.id.rankIconLayout).setVisibility(4);
                convertView.findViewById(R.id.menuRankLabel).setBackgroundResource(R.drawable.menu_rank_bg_disable);
                ((TextView) convertView.findViewById(R.id.menuRankLabel)).setText("-");
            } else {
                ((TextView) convertView.findViewById(R.id.menuRankLabel)).setText(model.getMenu_rank() + "\uc704");
            }
            int resourceId = R.drawable.menu_rank_new;
            if (model.getMenu_change().equals("U")) {
                resourceId = R.drawable.menu_rank_up;
            } else if (model.getMenu_change().equals("D")) {
                resourceId = R.drawable.menu_rank_down;
            } else if (model.getMenu_change().equals("K")) {
                resourceId = R.drawable.menu_rank_fix;
            }
            ((ImageView) convertView.findViewById(R.id.rankIconView)).setImageResource(resourceId);
        }
        return convertView;
    }
}