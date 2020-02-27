package com.nuvent.shareat.adapter.interest;

import android.content.Context;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.common.ViewerActivity;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.model.store.ReviewModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class ReviewAdapter extends BaseAdapter {
    /* access modifiers changed from: private */
    public Context mContext;
    private LayoutInflater mLayoutInflater;
    private ArrayList<ReviewModel> mReviewModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public String mTargetUserSno;

    class ViewHolder {
        TextView contents;
        TextView date;
        View form;
        View imgLayout;
        ImageView[] imgs;
        View nbbang;
        View reviewClickLayout;
        View space;
        TextView storeName;

        ViewHolder() {
        }
    }

    public ReviewAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return this.mReviewModels.size();
    }

    public Object getItem(int position) {
        return this.mReviewModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup viewGroup) {
        ViewHolder viewHolder;
        int i;
        int i2;
        int i3 = 8;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = this.mLayoutInflater.inflate(R.layout.cell_interest_review, null);
            viewHolder.reviewClickLayout = convertView.findViewById(R.id.reviewClickLayout);
            viewHolder.space = convertView.findViewById(R.id.space);
            viewHolder.form = convertView.findViewById(R.id.form);
            viewHolder.form.getLayoutParams().height = -2;
            viewHolder.nbbang = convertView.findViewById(R.id.nbbang);
            viewHolder.date = (TextView) convertView.findViewById(R.id.date);
            viewHolder.storeName = (TextView) convertView.findViewById(R.id.store_name);
            viewHolder.contents = (TextView) convertView.findViewById(R.id.contents);
            viewHolder.imgLayout = convertView.findViewById(R.id.img_layout);
            viewHolder.imgs = new ImageView[]{(ImageView) convertView.findViewById(R.id.img_1), (ImageView) convertView.findViewById(R.id.img_2), (ImageView) convertView.findViewById(R.id.img_3), (ImageView) convertView.findViewById(R.id.img_4), (ImageView) convertView.findViewById(R.id.img_5), (ImageView) convertView.findViewById(R.id.img_6)};
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        View view = viewHolder.space;
        if (position == 0) {
            i = 0;
        } else {
            i = 8;
        }
        view.setVisibility(i);
        final ReviewModel model = this.mReviewModels.get(position);
        View view2 = viewHolder.nbbang;
        if (model.isPaied()) {
            i2 = 0;
        } else {
            i2 = 8;
        }
        view2.setVisibility(i2);
        viewHolder.nbbang.setBackgroundResource(model.getResIdByPayType());
        viewHolder.date.setText(model.getDate());
        viewHolder.storeName.setText(model.getPartnerName());
        viewHolder.contents.setText(model.getContents());
        View view3 = viewHolder.imgLayout;
        if (model.hasImg()) {
            i3 = 0;
        }
        view3.setVisibility(i3);
        viewHolder.reviewClickLayout.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent(ReviewAdapter.this.mContext.getResources().getString(ReviewAdapter.this.mTargetUserSno == null ? R.string.ga_interest : R.string.ga_interest_target_user), ReviewAdapter.this.mContext.getResources().getString(R.string.ga_interest_review), ReviewAdapter.this.mContext.getResources().getString(R.string.store_detail));
                Intent intent = new Intent(ReviewAdapter.this.mContext, StoreDetailActivity.class);
                StoreModel storeModel = new StoreModel();
                storeModel.setPartnerName1(model.partner_name);
                storeModel.setPartnerSno(model.partner_sno);
                intent.putExtra("model", storeModel);
                ((BaseActivity) ReviewAdapter.this.mContext).pushActivity(intent);
            }
        });
        for (int i4 = 0; i4 < viewHolder.imgs.length; i4++) {
            if (i4 < model.getImg_list().size()) {
                viewHolder.imgs[i4].setVisibility(0);
                ImageDisplay.getInstance().displayImageLoad(model.getImg_list().get(i4).img_path, viewHolder.imgs[i4]);
                final int imageIndex = i4;
                viewHolder.imgs[i4].setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent(ReviewAdapter.this.mContext.getResources().getString(ReviewAdapter.this.mTargetUserSno == null ? R.string.ga_interest : R.string.ga_interest_target_user), ReviewAdapter.this.mContext.getResources().getString(R.string.ga_interest_review), ReviewAdapter.this.mContext.getResources().getString(R.string.photo_click));
                        Intent intent = new Intent(ReviewAdapter.this.mContext, ViewerActivity.class);
                        intent.putExtra("partnerSno", model.partner_sno);
                        intent.putExtra("feedSno", model.feed_sno);
                        intent.putExtra("index", imageIndex);
                        ((BaseActivity) ReviewAdapter.this.mContext).pushActivity(intent);
                    }
                });
            } else {
                viewHolder.imgs[i4].setVisibility(4);
            }
        }
        return convertView;
    }

    public void setData(ArrayList<ReviewModel> models) {
        this.mReviewModels = models;
        notifyDataSetChanged();
    }

    public void setTargetUserSno(String targetUserSno) {
        this.mTargetUserSno = targetUserSno;
    }
}