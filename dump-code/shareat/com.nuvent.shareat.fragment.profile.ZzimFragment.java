package com.nuvent.shareat.fragment.profile;

import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.adapter.interest.ZzimAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.interest.InterestApi;
import com.nuvent.shareat.manager.GpsManager;
import com.nuvent.shareat.model.store.ProfileStoreModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;

public class ZzimFragment extends Fragment {
    private static final int VIEW_COUNT = 10;
    /* access modifiers changed from: private */
    public boolean isFinish;
    /* access modifiers changed from: private */
    public boolean isLoading;
    /* access modifiers changed from: private */
    public TextView mEmptyLabel;
    private double mLatitude = 37.502336d;
    /* access modifiers changed from: private */
    public ListView mListView;
    private double mLongitude = 127.051936d;
    /* access modifiers changed from: private */
    public int mPageCount = 1;
    /* access modifiers changed from: private */
    public String mTargetUserSno;
    /* access modifiers changed from: private */
    public ZzimAdapter mZzimAdapter;
    /* access modifiers changed from: private */
    public ArrayList<ProfileStoreModel> mZzimModels = new ArrayList<>();

    @Nullable
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_interest_list, container, false);
        this.mZzimAdapter = new ZzimAdapter(getActivity());
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
        this.mListView.setAdapter(this.mZzimAdapter);
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                GAEvent.onGaEvent(ZzimFragment.this.getResources().getString(ZzimFragment.this.mTargetUserSno == null ? R.string.ga_interest : R.string.ga_interest_target_user), ZzimFragment.this.getResources().getString(R.string.ga_interest_zzim), ZzimFragment.this.getResources().getString(R.string.store_detail));
                Intent intent = new Intent(ZzimFragment.this.getActivity(), StoreDetailActivity.class);
                ProfileStoreModel profileStoreModel = (ProfileStoreModel) ZzimFragment.this.mZzimModels.get(position);
                StoreModel model = new StoreModel();
                model.setPartnerName1(profileStoreModel.getPartnerName1());
                model.setPartnerSno(profileStoreModel.getPartnerSno());
                model.setFavorite(profileStoreModel.getFavoriteYn());
                intent.putExtra("model", model);
                ZzimFragment.this.startActivity(intent);
            }
        });
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (ZzimFragment.this.mPageCount != 1 && totalItemCount - 1 <= firstVisibleItem + visibleItemCount && !ZzimFragment.this.isFinish && !ZzimFragment.this.isLoading) {
                    ZzimFragment.this.isLoading = true;
                    ZzimFragment.this.setVisitData();
                }
            }
        });
        setVisitData();
        return view;
    }

    public void setTargetUserSno(String userSno) {
        this.mTargetUserSno = userSno;
        if (this.mZzimAdapter != null) {
            setVisitData();
        }
    }

    public void setmTargetUserSno() {
        this.mTargetUserSno = null;
        setVisitData();
    }

    /* access modifiers changed from: private */
    public void setVisitData() {
        new InterestApi(getActivity(), ApiUrl.STORE_LIST + "?page=" + this.mPageCount + "&view_cnt=" + 10 + "&list_type=check&order_type=desc&target_user_sno=" + (this.mTargetUserSno == null ? ShareatApp.getInstance().getUserNum() : this.mTargetUserSno) + "&user_X=" + this.mLongitude + "&user_Y=" + this.mLatitude).request(new RequestHandler() {
            public void onStart() {
            }

            public void onResult(Object result) {
                ArrayList<ProfileStoreModel> models = (ArrayList) result;
                if (models.size() == 0) {
                    ZzimFragment.this.isFinish = true;
                }
                ZzimFragment.this.mZzimModels.addAll(models);
                if (ZzimFragment.this.mZzimModels.size() > 0) {
                    ZzimFragment.this.mZzimAdapter.setData(ZzimFragment.this.mZzimModels);
                    ZzimFragment.this.mPageCount = ZzimFragment.this.mPageCount + 1;
                } else if (ZzimFragment.this.mPageCount == 1) {
                    ZzimFragment.this.mListView.setVisibility(8);
                    ZzimFragment.this.mEmptyLabel.setVisibility(0);
                }
                ZzimFragment.this.isLoading = false;
            }

            public void onFailure(Exception exception) {
                ZzimFragment.this.isLoading = false;
            }
        });
    }
}