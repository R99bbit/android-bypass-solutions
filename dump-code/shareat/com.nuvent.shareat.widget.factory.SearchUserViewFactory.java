package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.search.SearchUserModel;
import net.xenix.util.ImageDisplay;

public class SearchUserViewFactory {
    public static View createView(Context context, SearchUserModel model) {
        View convertView = View.inflate(context, R.layout.cell_search_user, null);
        ((TextView) convertView.findViewById(R.id.nameLabel)).setText(model.getUserName());
        ImageView coverImageView = (ImageView) convertView.findViewById(R.id.coverImageView);
        if (model.getUserImg() != null && !model.getUserImg().isEmpty()) {
            ImageDisplay.getInstance().displayImageLoadRound(model.getUserImg(), coverImageView, context.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX), (int) R.drawable.list_user_none);
        }
        return convertView;
    }
}