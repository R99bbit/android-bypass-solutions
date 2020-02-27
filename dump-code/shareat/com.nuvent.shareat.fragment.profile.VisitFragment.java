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
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.adapter.interest.VisitAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.interest.InterestApi;
import com.nuvent.shareat.manager.GpsManager;
import com.nuvent.shareat.model.store.ProfileStoreModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;

public class VisitFragment extends Fragment {
    private static final int VIEW_COUNT = 10;
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
    public ArrayList<ProfileStoreModel> mProfileStoreModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public String mTargetUserSno;
    /* access modifiers changed from: private */
    public VisitAdapter mVisitAdapter;

    @Nullable
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_interest_list, container, false);
        this.isFinish = false;
        this.isLoading = false;
        this.mVisitAdapter = new VisitAdapter(getActivity());
        try {
            if (ShareatApp.getInstance().getGpsManager() == null) {
                GpsManager manager = ShareatApp.getInstance().getGpsManager();
                this.mLatitude = manager.getLatitude();
                this.mLongitude = manager.getLongitude();
            } else {
                this.mLatitude = 37.4986366d;
                this.mLongitude = 127.027021d;
            }
        } catch (Exception e) {
            this.mLatitude = 37.4986366d;
            this.mLongitude = 127.027021d;
        }
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mEmptyLabel = (TextView) view.findViewById(R.id.emptyLabel);
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                GAEvent.onGaEvent(VisitFragment.this.getResources().getString(VisitFragment.this.mTargetUserSno == null ? R.string.ga_interest : R.string.ga_interest_target_user), VisitFragment.this.getResources().getString(R.string.ga_interest_visit), VisitFragment.this.getResources().getString(R.string.store_detail));
                Intent intent = new Intent(VisitFragment.this.getActivity(), StoreDetailActivity.class);
                ProfileStoreModel profileStoreModel = (ProfileStoreModel) VisitFragment.this.mProfileStoreModels.get(position);
                StoreModel model = new StoreModel();
                model.setPartnerName1(profileStoreModel.getPartnerName1());
                model.setPartnerSno(profileStoreModel.getPartnerSno());
                model.setFavorite(profileStoreModel.getFavoriteYn());
                intent.putExtra("model", model);
                VisitFragment.this.startActivity(intent);
            }
        });
        this.mListView.setAdapter(this.mVisitAdapter);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (VisitFragment.this.mPageCount != 1 && totalItemCount - 1 <= firstVisibleItem + visibleItemCount && !VisitFragment.this.isFinish && !VisitFragment.this.isLoading) {
                    VisitFragment.this.isLoading = true;
                    VisitFragment.this.setVisitData();
                }
            }
        });
        return view;
    }

    public void setTargetUserSno(String userSno) {
        this.mTargetUserSno = userSno;
        setVisitData();
    }

    public void setmTargetUserSno() {
        this.mTargetUserSno = null;
        setVisitData();
    }

    /* access modifiers changed from: private */
    public void setVisitData() {
        new InterestApi(getActivity(), ApiUrl.STORE_LIST + "?page=" + this.mPageCount + "&view_cnt=" + 10 + "&list_type=favorite&order_type=desc&target_user_sno=" + (this.mTargetUserSno == null ? ShareatApp.getInstance().getUserNum() : this.mTargetUserSno) + "&user_X=" + this.mLongitude + "&user_Y=" + this.mLatitude).request(new RequestHandler() {
            public void onStart() {
                if (1 == VisitFragment.this.mPageCount) {
                    ((BaseActivity) VisitFragment.this.getActivity()).showCircleDialog(true);
                }
            }

            public void onResult(Object result) {
                ((BaseActivity) VisitFragment.this.getActivity()).showCircleDialog(false);
                ArrayList<ProfileStoreModel> models = (ArrayList) result;
                if (models.size() == 0) {
                    VisitFragment.this.isFinish = true;
                }
                VisitFragment.this.mProfileStoreModels.addAll(models);
                if (VisitFragment.this.mProfileStoreModels.size() > 0) {
                    VisitFragment.this.mVisitAdapter.setData(VisitFragment.this.mProfileStoreModels);
                    VisitFragment.this.mPageCount = VisitFragment.this.mPageCount + 1;
                } else if (VisitFragment.this.mPageCount == 1) {
                    VisitFragment.this.mListView.setVisibility(8);
                    VisitFragment.this.mEmptyLabel.setVisibility(0);
                }
                VisitFragment.this.isLoading = false;
            }

            public void onFailure(Exception exception) {
                VisitFragment.this.isLoading = false;
                if (VisitFragment.this.getActivity() != null) {
                    ((BaseActivity) VisitFragment.this.getActivity()).showCircleDialog(false);
                }
            }
        });
    }
}