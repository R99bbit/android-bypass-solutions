package com.nuvent.shareat.activity.common;

import android.os.Bundle;
import android.view.View;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.GridView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreAllImageListApi;
import com.nuvent.shareat.api.store.StoreReviewApi;
import com.nuvent.shareat.event.ImageListEvent;
import com.nuvent.shareat.model.store.ReviewImageModel;
import com.nuvent.shareat.model.store.ReviewInfoResultModel;
import com.nuvent.shareat.model.store.StoreAllImageModel;
import com.nuvent.shareat.model.store.StoreAllImageResultModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.widget.factory.ReviewImageGridViewFactory;
import com.nuvent.shareat.widget.factory.StoreImageGridViewFactory;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class ImageListActivity extends MainActionBarActivity {
    private static final int IMAGE_ITEM_LIMIT_COUNT = 20;
    private static final int VIEWER_TYPE_REVIEW = 2;
    private static final int VIEWER_TYPE_STORE = 1;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    private String mFeedSno;
    /* access modifiers changed from: private */
    public GridView mGridView;
    /* access modifiers changed from: private */
    public boolean mHasMoreItem = true;
    private StoreDetailModel mModel;
    private ArrayList<StoreAllImageModel> mModels;
    /* access modifiers changed from: private */
    public int mPage = 1;
    private String mPartnerSno;
    /* access modifiers changed from: private */
    public ReferenceAdapter<ReviewImageModel> mReviewImageAdapter;
    /* access modifiers changed from: private */
    public ReviewInfoResultModel mReviewModel;
    /* access modifiers changed from: private */
    public ReferenceAdapter<StoreAllImageModel> mStoreImageAdapter;
    /* access modifiers changed from: private */
    public int mTotalCount = 0;
    private int mViewerType = 1;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_imagelist, 2);
        showFavoriteButton(false);
        showSubActionbar();
        setTitle("\uc0ac\uc9c4");
        this.mGridView = (GridView) findViewById(R.id.gridView);
        if (getIntent().hasExtra("model")) {
            this.mModels = new ArrayList<>();
            this.mModel = (StoreDetailModel) getIntent().getSerializableExtra("model");
            if (this.mModel != null) {
                this.mViewerType = 1;
                setStoreAdapter();
                requestAllImageListApi();
            }
        } else if (getIntent().hasExtra("feedSno")) {
            this.mViewerType = 2;
            this.mPartnerSno = getIntent().getStringExtra("partnerSno");
            this.mFeedSno = getIntent().getStringExtra("feedSno");
            if (getIntent().hasExtra("imageModel")) {
                this.mReviewModel = (ReviewInfoResultModel) getIntent().getSerializableExtra("imageModel");
                setReviewAdapter();
                this.mTotalCount = this.mReviewModel.getImg_list().size();
                this.mReviewImageAdapter.addAll(this.mReviewModel.getImg_list());
                this.mReviewImageAdapter.notifyDataSetChanged();
                this.mTotalCount = this.mReviewModel.getImg_list().size();
                return;
            }
            this.mReviewModel = new ReviewInfoResultModel();
            setReviewAdapter();
            requestReviewInfoApi();
        }
    }

    private void setReviewAdapter() {
        this.mReviewImageAdapter = new ReferenceAdapter<>(new AdapterViewProvider<ReviewImageModel>() {
            public View getView(ReviewImageModel model, int position) {
                return ReviewImageGridViewFactory.createView(ImageListActivity.this, model, position);
            }

            public void viewWillDisplay(View view, ReviewImageModel model) {
            }
        });
        this.mGridView.setAdapter(this.mReviewImageAdapter.getAdapter());
    }

    private void setStoreAdapter() {
        this.mStoreImageAdapter = new ReferenceAdapter<>(new AdapterViewProvider<StoreAllImageModel>() {
            public View getView(StoreAllImageModel model, int position) {
                return StoreImageGridViewFactory.createView(ImageListActivity.this, model, position);
            }

            public void viewWillDisplay(View view, StoreAllImageModel model) {
            }
        });
        this.mGridView.setAdapter(this.mStoreImageAdapter.getAdapter());
        this.mGridView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (ImageListActivity.this.mStoreImageAdapter != null && ImageListActivity.this.mStoreImageAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !ImageListActivity.this.mApiRequesting && ImageListActivity.this.mHasMoreItem) {
                    ImageListActivity.this.requestAllImageListApi();
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestAllImageListApi() {
        this.mApiRequesting = true;
        String params = String.format("?partner_sno=%d&page=%d&view_cnt=%d", new Object[]{Integer.valueOf(this.mModel.getPartner_sno()), Integer.valueOf(this.mPage), Integer.valueOf(20)});
        StoreAllImageListApi request = new StoreAllImageListApi(this);
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreAllImageResultModel model = (StoreAllImageResultModel) result;
                ImageListActivity.this.mTotalCount = model.getTotal_cnt();
                if (model.getResult_list() == null || model.getResult_list().size() <= 0) {
                    ImageListActivity.this.mHasMoreItem = false;
                    return;
                }
                if (ImageListActivity.this.mPage == 1) {
                    ImageListActivity.this.mStoreImageAdapter.clear();
                    ImageListActivity.this.mStoreImageAdapter.addAll(model.getResult_list());
                    ImageListActivity.this.mGridView.setAdapter(ImageListActivity.this.mStoreImageAdapter.getAdapter());
                } else if (model.getResult_list().size() > 0) {
                    ImageListActivity.this.mStoreImageAdapter.addAll(model.getResult_list());
                    ImageListActivity.this.mStoreImageAdapter.notifyDataSetChanged();
                }
                if (20 > model.getResult_list().size()) {
                    ImageListActivity.this.mHasMoreItem = false;
                } else {
                    ImageListActivity.this.mPage = ImageListActivity.this.mPage + 1;
                }
                EventBus.getDefault().post(new ImageListEvent(ImageListActivity.this.mStoreImageAdapter.getModels()));
            }

            public void onFailure(Exception exception) {
                exception.printStackTrace();
                ImageListActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ImageListActivity.this.requestAllImageListApi();
                    }
                });
            }

            public void onFinish() {
                ImageListActivity.this.mApiRequesting = false;
                ((TextView) ImageListActivity.this.findViewById(R.id.countLabel)).setText(String.valueOf(ImageListActivity.this.mTotalCount));
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestReviewInfoApi() {
        String params = String.format("?partner_sno=%s&feed_sno=%s", new Object[]{this.mPartnerSno, this.mFeedSno});
        StoreReviewApi request = new StoreReviewApi(this);
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onStart() {
                ImageListActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                ImageListActivity.this.showCircleDialog(false);
                ReviewInfoResultModel model = (ReviewInfoResultModel) result;
                ImageListActivity.this.mTotalCount = model.getImg_list().size();
                if (model != null && model.getResult().equals("Y")) {
                    ImageListActivity.this.mReviewModel = model;
                    ImageListActivity.this.mReviewImageAdapter.addAll(ImageListActivity.this.mReviewModel.getImg_list());
                    ImageListActivity.this.mReviewImageAdapter.notifyDataSetChanged();
                    ImageListActivity.this.mTotalCount = ImageListActivity.this.mReviewModel.getImg_list().size();
                }
            }

            public void onFailure(Exception exception) {
                ImageListActivity.this.showCircleDialog(false);
                ImageListActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ImageListActivity.this.requestReviewInfoApi();
                    }
                });
            }

            public void onFinish() {
                ImageListActivity.this.showCircleDialog(false);
                ((TextView) ImageListActivity.this.findViewById(R.id.countLabel)).setText(String.valueOf(ImageListActivity.this.mTotalCount));
            }
        });
    }
}