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
import com.nuvent.shareat.adapter.interest.PhotoAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.interest.PhotoApi;
import com.nuvent.shareat.manager.GpsManager;
import com.nuvent.shareat.model.store.ReviewImageModel;
import java.util.ArrayList;

public class PhotoFragment extends Fragment {
    private static final int VIEW_COUNT = 15;
    /* access modifiers changed from: private */
    public boolean isFinish;
    /* access modifiers changed from: private */
    public boolean isLoading;
    /* access modifiers changed from: private */
    public TextView mEmptyLabel;
    private double mLatitude;
    /* access modifiers changed from: private */
    public ListView mListView;
    private double mLongitude;
    /* access modifiers changed from: private */
    public int mPageCount = 1;
    /* access modifiers changed from: private */
    public PhotoAdapter mPhotoAdapter;
    /* access modifiers changed from: private */
    public ArrayList<ReviewImageModel> mPhotoModels;
    private String mTargetUserSno;

    @Nullable
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_photo_list, container, false);
        this.mPhotoAdapter = new PhotoAdapter(getActivity());
        this.mPhotoModels = new ArrayList<>();
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
        this.mListView.setAdapter(this.mPhotoAdapter);
        this.mPhotoAdapter.setTargetUserSno(this.mTargetUserSno);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (PhotoFragment.this.mPageCount != 1 && totalItemCount - 1 <= firstVisibleItem + visibleItemCount && !PhotoFragment.this.isFinish && !PhotoFragment.this.isLoading) {
                    PhotoFragment.this.isLoading = true;
                    PhotoFragment.this.setVisitData();
                }
            }
        });
        setVisitData();
        return view;
    }

    public void setTargetUserSno(String userSno) {
        this.mTargetUserSno = userSno;
        if (this.mPhotoAdapter != null) {
            this.mPhotoAdapter.setTargetUserSno(this.mTargetUserSno);
            setVisitData();
        }
    }

    public void setmTargetUserSno() {
        this.mTargetUserSno = null;
        setVisitData();
    }

    /* access modifiers changed from: private */
    public void setVisitData() {
        new PhotoApi(getActivity(), ApiUrl.PROFILE_PHOTO_LIST + "?page=" + this.mPageCount + "&view_cnt=" + 15 + "&list_type=img_sno&order_type=desc&target_user_sno=" + (this.mTargetUserSno == null ? ShareatApp.getInstance().getUserNum() : this.mTargetUserSno)).request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                ArrayList<ReviewImageModel> models = (ArrayList) result;
                if (models.size() == 0) {
                    PhotoFragment.this.isFinish = true;
                }
                PhotoFragment.this.mPhotoModels.addAll(models);
                if (PhotoFragment.this.mPhotoModels.size() > 0) {
                    PhotoFragment.this.mPhotoAdapter.setData(PhotoFragment.this.mPhotoModels);
                    PhotoFragment.this.mPageCount = PhotoFragment.this.mPageCount + 1;
                } else if (PhotoFragment.this.mPageCount == 1) {
                    PhotoFragment.this.mListView.setVisibility(8);
                    PhotoFragment.this.mEmptyLabel.setVisibility(0);
                }
                PhotoFragment.this.isLoading = false;
            }

            public void onFailure(Exception exception) {
                PhotoFragment.this.isLoading = false;
            }
        });
    }
}