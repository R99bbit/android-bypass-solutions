package com.nuvent.shareat.adapter.interest;

import android.content.Context;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout.LayoutParams;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.common.ViewerActivity;
import com.nuvent.shareat.model.store.ReviewImageModel;
import com.nuvent.shareat.model.store.ReviewInfoResultModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class PhotoAdapter extends BaseAdapter {
    /* access modifiers changed from: private */
    public Context mContext;
    private LayoutInflater mLayoutInflater;
    /* access modifiers changed from: private */
    public ArrayList<ReviewImageModel> mPhotoModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public String mTargetUserSno;

    class ViewHolder {
        ImageView[] imgs;

        ViewHolder() {
        }
    }

    public PhotoAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return (this.mPhotoModels.size() % 3 > 0 ? 1 : 0) + (this.mPhotoModels.size() / 3);
    }

    public Object getItem(int position) {
        int position2 = Math.min(position * 3, this.mPhotoModels.size() - 1);
        return this.mPhotoModels.subList(position2, Math.min(position2 + 1, this.mPhotoModels.size()));
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup viewGroup) {
        ViewHolder viewHolder;
        ImageView[] imageViewArr;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = this.mLayoutInflater.inflate(R.layout.cell_interest_photo, null);
            viewHolder.imgs = new ImageView[]{(ImageView) convertView.findViewById(R.id.imageButton1), (ImageView) convertView.findViewById(R.id.imageButton2), (ImageView) convertView.findViewById(R.id.imageButton3)};
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        for (ImageView imageview : viewHolder.imgs) {
            imageview.setImageBitmap(null);
        }
        ImageDisplay.getInstance().displayImageLoadThumb(this.mPhotoModels.get(position * 3).getImg_url(), viewHolder.imgs[0], this.mContext.getResources().getDimensionPixelSize(R.dimen.INTEREST_PHOTO_ROUND_SIZE));
        if (this.mPhotoModels.size() > (position * 3) + 1) {
            viewHolder.imgs[1].setVisibility(0);
            ImageDisplay.getInstance().displayImageLoadThumb(this.mPhotoModels.get((position * 3) + 1).getImg_url(), viewHolder.imgs[1], this.mContext.getResources().getDimensionPixelSize(R.dimen.INTEREST_PHOTO_ROUND_SIZE));
        } else {
            viewHolder.imgs[1].setVisibility(4);
        }
        if (this.mPhotoModels.size() > (position * 3) + 2) {
            viewHolder.imgs[2].setVisibility(0);
            ImageDisplay.getInstance().displayImageLoadThumb(this.mPhotoModels.get((position * 3) + 2).getImg_url(), viewHolder.imgs[2], this.mContext.getResources().getDimensionPixelSize(R.dimen.INTEREST_PHOTO_ROUND_SIZE));
        } else {
            viewHolder.imgs[2].setVisibility(4);
        }
        for (int i = 0; i < viewHolder.imgs.length; i++) {
            final int imageIndex = i;
            final int i2 = position;
            viewHolder.imgs[i].setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    GAEvent.onGaEvent(PhotoAdapter.this.mContext.getResources().getString(PhotoAdapter.this.mTargetUserSno == null ? R.string.ga_interest : R.string.ga_interest_target_user), PhotoAdapter.this.mContext.getResources().getString(R.string.ga_interest_photo), PhotoAdapter.this.mContext.getResources().getString(R.string.photo_click));
                    ReviewInfoResultModel reviewInfoResultModel = new ReviewInfoResultModel();
                    reviewInfoResultModel.setImg_list(PhotoAdapter.this.mPhotoModels);
                    ReviewImageModel reviewImageModel = (ReviewImageModel) PhotoAdapter.this.mPhotoModels.get((i2 * 3) + imageIndex);
                    Intent intent = new Intent(PhotoAdapter.this.mContext, ViewerActivity.class);
                    intent.putExtra("partnerSno", reviewImageModel.partner_sno);
                    intent.putExtra("feedSno", reviewImageModel.feed_sno);
                    intent.putExtra("index", (i2 * 3) + imageIndex);
                    intent.putExtra("imageModel", reviewInfoResultModel);
                    PhotoAdapter.this.mContext.startActivity(intent);
                }
            });
        }
        for (ImageView imageView : viewHolder.imgs) {
            LayoutParams params = (LayoutParams) imageView.getLayoutParams();
            params.height = imageView.getWidth();
            imageView.setLayoutParams(params);
        }
        return convertView;
    }

    public void setTargetUserSno(String targetUserSno) {
        this.mTargetUserSno = targetUserSno;
    }

    public void setData(ArrayList<ReviewImageModel> models) {
        this.mPhotoModels = models;
        notifyDataSetChanged();
    }
}