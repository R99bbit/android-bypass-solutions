package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.common.WebReviewActivity;
import com.nuvent.shareat.model.store.StoreBlogModel;
import com.nuvent.shareat.util.GAEvent;
import net.xenix.util.ImageDisplay;

public class StoreBlogView extends FrameLayout {
    /* access modifiers changed from: private */
    public Context mContext;

    public StoreBlogView(Context context) {
        super(context);
        init(context);
    }

    public StoreBlogView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public StoreBlogView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        this.mContext = context;
        View.inflate(context, R.layout.cell_store_blog, this);
    }

    public void setData(final StoreBlogModel model) {
        int size;
        setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                int resourceId;
                if (model.getPostType().contains("\ube14\ub85c\uadf8")) {
                    resourceId = R.string.StoreDetail_Review_Detail_NaverBlog;
                } else {
                    resourceId = R.string.StoreDetail_Review_Detail_NaverCafe;
                }
                GAEvent.onGaEvent((Activity) (BaseActivity) StoreBlogView.this.mContext, (int) R.string.ga_store_detail, (int) R.string.StoreDetail_Review_SNS, resourceId);
                Intent intent = new Intent(new Intent(StoreBlogView.this.mContext, WebReviewActivity.class));
                intent.putExtra("title", model.getTitle());
                intent.putExtra("url", model.getLinkUrl());
                ((BaseActivity) StoreBlogView.this.mContext).modalActivity(intent);
            }
        });
        ((TextView) findViewById(R.id.titleLabel)).setText(model.getTitle());
        ((TextView) findViewById(R.id.descriptionLabel)).setText(model.getSnippet());
        ((TextView) findViewById(R.id.blogLabel)).setText(model.getPostType());
        ((TextView) findViewById(R.id.dateLabel)).setText(model.getPostDate());
        if (model.getReviewImgList() == null || model.getReviewImgList().size() <= 0) {
            findViewById(R.id.imageLayout).setVisibility(8);
            return;
        }
        findViewById(R.id.imageLayout).setVisibility(0);
        ((LinearLayout) findViewById(R.id.imageLayout)).removeAllViews();
        int imageSize = getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_15OPX);
        int i = 0;
        while (true) {
            if (6 < model.getReviewImgList().size()) {
                size = 6;
            } else {
                size = model.getReviewImgList().size();
            }
            if (i < size) {
                ImageView reviewImage = new ImageView(this.mContext);
                reviewImage.setBackgroundResource(R.drawable.blog_img);
                ((ViewGroup) findViewById(R.id.imageLayout)).addView(reviewImage);
                reviewImage.getLayoutParams().height = imageSize;
                reviewImage.getLayoutParams().width = imageSize;
                reviewImage.setScaleType(ScaleType.CENTER_CROP);
                if (i > 0) {
                    ((LayoutParams) reviewImage.getLayoutParams()).leftMargin = getResources().getDimensionPixelOffset(R.dimen.STORE_REVIEW_IMAGE_MARGIN);
                }
                ImageDisplay.getInstance().displayImageLoad(model.getReviewImgList().get(i), reviewImage);
                i++;
            } else {
                return;
            }
        }
    }

    public void setBackground(int resId) {
        ((LinearLayout) findViewById(R.id.rootLayout)).setBackgroundResource(resId);
    }
}