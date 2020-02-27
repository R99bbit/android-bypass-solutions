package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.common.WebReviewActivity;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.util.GAEvent;
import net.xenix.util.ImageDisplay;

public class StoreInstaView extends FrameLayout {
    /* access modifiers changed from: private */
    public Context mContext;

    public StoreInstaView(Context context) {
        super(context);
        init(context);
    }

    public StoreInstaView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public StoreInstaView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        this.mContext = context;
        View.inflate(context, R.layout.cell_store_insta, this);
    }

    public void setData(StoreInstaModel firstModel, StoreInstaModel secondModel) {
        final StoreInstaModel storeInstaModel = firstModel;
        findViewById(R.id.firstLayout).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) StoreInstaView.this.mContext, (int) R.string.ga_store_detail, (int) R.string.StoreDetail_Review_SNS, (int) R.string.StoreDetail_Review_Detail_Insta);
                Intent intent = new Intent(new Intent(StoreInstaView.this.mContext, WebReviewActivity.class));
                intent.putExtra("insta", "");
                intent.putExtra("storeName", storeInstaModel.getPartnerName1());
                intent.putExtra("userName", storeInstaModel.getUserName());
                intent.putExtra("date", storeInstaModel.getTermEvent());
                intent.putExtra("url", storeInstaModel.getLinkUrl());
                ((BaseActivity) StoreInstaView.this.mContext).modalActivity(intent);
            }
        });
        ImageDisplay.getInstance().displayImageLoad(firstModel.getContentsImgUrl(), (ImageView) findViewById(R.id.firstImageView));
        ImageDisplay.getInstance().displayImageLoadListRound(firstModel.getUserProfileImgUrl(), (ImageView) findViewById(R.id.firstProfileImageView), getResources().getDimensionPixelOffset(R.dimen.DETAIL_INSTAGRAM_PROFILE));
        ((TextView) findViewById(R.id.firstNameLabel)).setText(firstModel.getUserName());
        ((TextView) findViewById(R.id.firstTimeLabel)).setText(firstModel.getTermEvent());
        ((TextView) findViewById(R.id.firstLikeCountLabel)).setText(firstModel.getLikesCount());
        ((TextView) findViewById(R.id.firstContentLabel)).setText(firstModel.getTitle());
        if (secondModel == null) {
            findViewById(R.id.secondLayout).setVisibility(4);
            return;
        }
        final StoreInstaModel storeInstaModel2 = secondModel;
        findViewById(R.id.secondLayout).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) StoreInstaView.this.mContext, (int) R.string.ga_store_detail, (int) R.string.StoreDetail_Review_SNS, (int) R.string.StoreDetail_Review_Detail_Insta);
                Intent intent = new Intent(new Intent(StoreInstaView.this.mContext, WebReviewActivity.class));
                intent.putExtra("insta", "");
                intent.putExtra("storeName", storeInstaModel2.getPartnerName1());
                intent.putExtra("userName", storeInstaModel2.getUserName());
                intent.putExtra("date", storeInstaModel2.getTermEvent());
                intent.putExtra("url", storeInstaModel2.getLinkUrl());
                ((BaseActivity) StoreInstaView.this.mContext).modalActivity(intent);
            }
        });
        findViewById(R.id.secondLayout).setVisibility(0);
        ImageDisplay.getInstance().displayImageLoad(secondModel.getContentsImgUrl(), (ImageView) findViewById(R.id.secondImageView));
        ImageDisplay.getInstance().displayImageLoadListRound(secondModel.getUserProfileImgUrl(), (ImageView) findViewById(R.id.secondProfileImageView), getResources().getDimensionPixelOffset(R.dimen.DETAIL_INSTAGRAM_PROFILE));
        ((TextView) findViewById(R.id.secondNameLabel)).setText(secondModel.getUserName());
        ((TextView) findViewById(R.id.secondTimeLabel)).setText(secondModel.getTermEvent());
        ((TextView) findViewById(R.id.secondLikeCountLabel)).setText(secondModel.getLikesCount());
        ((TextView) findViewById(R.id.secondContentLabel)).setText(secondModel.getTitle());
    }

    public void clearData() {
        ((ImageView) findViewById(R.id.firstImageView)).setImageBitmap(null);
        ((ImageView) findViewById(R.id.firstProfileImageView)).setImageBitmap(null);
        ((ImageView) findViewById(R.id.secondImageView)).setImageBitmap(null);
        ((ImageView) findViewById(R.id.secondProfileImageView)).setImageBitmap(null);
    }
}