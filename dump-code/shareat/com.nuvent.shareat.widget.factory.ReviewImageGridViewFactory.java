package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ImageView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.event.ImageClickEvent;
import com.nuvent.shareat.model.store.ReviewImageModel;
import de.greenrobot.event.EventBus;
import net.xenix.util.ImageDisplay;

public class ReviewImageGridViewFactory {
    public static View createView(final Context context, ReviewImageModel model, final int position) {
        View convertView = View.inflate(context, R.layout.cell_image_list, null);
        String imgPath = model.getImg_real();
        if (imgPath == null || true == imgPath.isEmpty()) {
            imgPath = model.getImg_url();
        }
        ImageDisplay.getInstance().displayImageLoadThumb(imgPath, (ImageView) convertView.findViewById(R.id.firstImageView), context.getResources().getDimensionPixelSize(R.dimen.CARD_VIEW_OPEN_MARGIN));
        convertView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                EventBus.getDefault().post(new ImageClickEvent(position));
                ((BaseActivity) context).finish();
            }
        });
        return convertView;
    }
}