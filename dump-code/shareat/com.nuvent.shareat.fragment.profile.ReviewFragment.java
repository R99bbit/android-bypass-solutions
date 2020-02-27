package com.nuvent.shareat.fragment.profile;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.ListView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.adapter.interest.ReviewAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.interest.ReviewApi;
import com.nuvent.shareat.manager.GpsManager;
import com.nuvent.shareat.model.store.ReviewModel;
import java.util.ArrayList;

public class ReviewFragment extends Fragment {
    private static final int VIEW_COUNT = 10;
    /* access modifiers changed from: private */
    public boolean isFinish;
    /* access modifiers changed from: private */
    public boolean isLoading;
    TextView mEmptyLabel;
    private double mLatitude;
    ListView mListView;
    private double mLongitude;
    /* access modifiers changed from: private */
    public int mPageCount = 1;
    /* access modifiers changed from: private */
    public ReviewAdapter mReviewAdapter;
    /* access modifiers changed from: private */
    public ArrayList<ReviewModel> mReviewModels;
    private String mTargetUserSno;

    @Nullable
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_review_list, container, false);
        this.mReviewAdapter = new ReviewAdapter(getActivity());
        this.mReviewModels = new ArrayList<>();
        this.isFinish = false;
        this.isLoading = false;
        try {
            GpsManager manager = ShareatApp.getInstance().getGpsManager();
            this.mLatitude = manager.getLatitude();
            this.mLongitude = manager.getLongitude();
        } catch (Exception e) {
            this.mLatitude = 37.4986366d;
            this.mLongitude = 127.027021d;
        }
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mEmptyLabel = (TextView) view.findViewById(R.id.emptyLabel);
        this.mListView.setAdapter(this.mReviewAdapter);
        this.mReviewAdapter.setTargetUserSno(this.mTargetUserSno);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (ReviewFragment.this.mPageCount != 1 && totalItemCount - 1 <= firstVisibleItem + visibleItemCount && !ReviewFragment.this.isFinish && !ReviewFragment.this.isLoading) {
                    ReviewFragment.this.isLoading = true;
                    ReviewFragment.this.setVisitData();
                }
            }
        });
        setVisitData();
        return view;
    }

    public void setTargetUserSno(String userSno) {
        this.mTargetUserSno = userSno;
        if (this.mReviewAdapter != null) {
            this.mReviewAdapter.setTargetUserSno(this.mTargetUserSno);
            setVisitData();
        }
    }

    public void setTargetUserSno() {
        this.mTargetUserSno = null;
        setVisitData();
    }

    /* access modifiers changed from: private */
    public void setVisitData() {
        new ReviewApi(getActivity(), ApiUrl.REVIEW_LIST + "?page=" + this.mPageCount + "&view_cnt=" + 10 + "&target_user_sno=" + (this.mTargetUserSno == null ? ShareatApp.getInstance().getUserNum() : this.mTargetUserSno)).request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                ArrayList<ReviewModel> models = (ArrayList) result;
                if (models.size() == 0) {
                    ReviewFragment.this.isFinish = true;
                }
                ReviewFragment.this.mReviewModels.addAll(models);
                if (ReviewFragment.this.mReviewModels.size() > 0) {
                    ReviewFragment.this.mReviewAdapter.setData(ReviewFragment.this.mReviewModels);
                    ReviewFragment.this.mPageCount = ReviewFragment.this.mPageCount + 1;
                } else if (ReviewFragment.this.mPageCount == 1) {
                    ReviewFragment.this.mListView.setVisibility(8);
                    ReviewFragment.this.mEmptyLabel.setVisibility(0);
                }
                ReviewFragment.this.isLoading = false;
            }

            public void onFailure(Exception exception) {
                ReviewFragment.this.isLoading = false;
            }
        });
    }
}