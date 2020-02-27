package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.ReviewModel;
import com.nuvent.shareat.model.store.StoreBlogModel;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.widget.view.EmptyTabView;
import com.nuvent.shareat.widget.view.ReviewView;
import com.nuvent.shareat.widget.view.StoreBlogView;
import com.nuvent.shareat.widget.view.StoreInstaView;

public class ReviewListFactory extends FrameLayout {
    private EmptyTabView mEmptyTabView;
    /* access modifiers changed from: private */
    public OnClickView mListener;
    private ReviewView mReviewView;
    private StoreBlogView mStoreBlogView;
    private StoreInstaView mStoreInstaView;

    public interface OnClickView {
        void onClickDelete();

        void onClickEdit();

        void onClickLike(View view);
    }

    public ReviewListFactory(Context context) {
        super(context);
        init(context);
    }

    public ReviewListFactory(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public ReviewListFactory(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        View.inflate(context, R.layout.cell_store_list, this);
        FrameLayout rootLayout = (FrameLayout) findViewById(R.id.rootLayout);
        this.mReviewView = new ReviewView(context);
        this.mStoreBlogView = new StoreBlogView(context);
        this.mStoreInstaView = new StoreInstaView(context);
        this.mEmptyTabView = new EmptyTabView(context);
        rootLayout.addView(this.mReviewView);
        rootLayout.addView(this.mStoreBlogView);
        rootLayout.addView(this.mStoreInstaView);
        rootLayout.addView(this.mEmptyTabView);
    }

    public void setData(ReviewModel model, int position, Typeface typeface) {
        this.mStoreBlogView.setVisibility(8);
        this.mStoreInstaView.setVisibility(8);
        this.mReviewView.setVisibility(0);
        this.mEmptyTabView.setVisibility(8);
        this.mReviewView.setData(model, typeface);
        if (position == 1) {
            this.mStoreBlogView.setBackground(R.drawable.blog_cell_first_bg);
        } else {
            this.mStoreBlogView.setBackground(R.drawable.blog_cell_bg);
        }
        this.mReviewView.setOnClickViewListener(new com.nuvent.shareat.widget.view.ReviewView.OnClickView() {
            public void onClickLike(View view) {
                ReviewListFactory.this.mListener.onClickLike(view);
            }

            public void onClickDelete() {
                ReviewListFactory.this.mListener.onClickDelete();
            }

            public void onClickEdit() {
                ReviewListFactory.this.mListener.onClickEdit();
            }
        });
    }

    public void setData(StoreBlogModel model) {
        this.mReviewView.setVisibility(8);
        this.mStoreInstaView.setVisibility(8);
        this.mStoreBlogView.setVisibility(0);
        this.mEmptyTabView.setVisibility(8);
        this.mStoreBlogView.setData(model);
    }

    public void setData(StoreInstaModel firstModel, StoreInstaModel secondModel) {
        this.mStoreBlogView.setVisibility(8);
        this.mReviewView.setVisibility(8);
        this.mStoreInstaView.setVisibility(0);
        this.mEmptyTabView.setVisibility(8);
        this.mStoreInstaView.setData(firstModel, secondModel);
    }

    public void setEmpty(int size) {
        this.mEmptyTabView.setSize(size);
        this.mEmptyTabView.setVisibility(0);
        this.mStoreBlogView.setVisibility(8);
        this.mReviewView.setVisibility(8);
        this.mStoreInstaView.setVisibility(8);
    }

    public void clearData() {
        this.mStoreInstaView.clearData();
    }

    public void setOnClickViewListener(OnClickView listener) {
        this.mListener = listener;
    }
}