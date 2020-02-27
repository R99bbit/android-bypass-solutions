package com.nuvent.shareat.fragment;

import android.app.Activity;
import android.os.Bundle;
import android.support.graphics.drawable.PathInterpolatorCompat;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ExpandableListView;
import android.widget.ExpandableListView.OnGroupCollapseListener;
import android.widget.ExpandableListView.OnGroupExpandListener;
import android.widget.ImageView;
import android.widget.TextView;
import com.facebook.appevents.AppEventsConstants;
import com.nostra13.universalimageloader.core.download.BaseImageDownloader;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.adapter.LocationAdapter;
import com.nuvent.shareat.adapter.LocationAdapter.OnClickCell;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreAreaListApi;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.manager.app.ParamManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.store.LocationModel;
import com.nuvent.shareat.model.store.LocationResultModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;

public class LocationFragment extends Fragment {
    /* access modifiers changed from: private */
    public LocationAdapter mAdapter;
    private OnClickListener mDistanceClickListener = new OnClickListener() {
        public void onClick(View v) {
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(4);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(4);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine03).setVisibility(4);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine04).setVisibility(4);
            ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.current_pin_small);
            ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.current_pin_small);
            ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin03)).setImageResource(R.drawable.current_pin_small);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin01).setVisibility(8);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin02).setVisibility(8);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin03).setVisibility(8);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin04).setVisibility(8);
            LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin05).setVisibility(8);
            int distance = 0;
            switch (Integer.parseInt((String) v.getTag())) {
                case 1:
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin01).setVisibility(0);
                    break;
                case 2:
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin02).setVisibility(0);
                    distance = 500;
                    break;
                case 3:
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(0);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.select_pin_small);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin03).setVisibility(0);
                    distance = 1000;
                    break;
                case 4:
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(0);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine03).setVisibility(0);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.select_pin_small);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin03)).setImageResource(R.drawable.select_pin_small);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin04).setVisibility(0);
                    distance = PathInterpolatorCompat.MAX_NUM_POINTS;
                    break;
                case 5:
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(0);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine03).setVisibility(0);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedLine04).setVisibility(0);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.select_pin_small);
                    ((ImageView) LocationFragment.this.mHeaderView.findViewById(R.id.smallPin03)).setImageResource(R.drawable.select_pin_small);
                    LocationFragment.this.mHeaderView.findViewById(R.id.selectedPin05).setVisibility(0);
                    distance = BaseImageDownloader.DEFAULT_HTTP_CONNECT_TIMEOUT;
                    break;
            }
            ParamManager.getInstance().setLimitDistance(distance);
            GAEvent.onGaEvent(LocationFragment.this.getActivity(), R.string.gnb_location, R.string.ga_ev_click, R.string.gnb_location_near, String.valueOf(distance) + "m");
            ParamManager.getInstance().setRecentSetModel(new LocationModel());
            ((MainActivity) LocationFragment.this.getActivity()).onClickGnbOption();
        }
    };
    /* access modifiers changed from: private */
    public View mHeaderView;
    /* access modifiers changed from: private */
    public ExpandableListView mListView;
    /* access modifiers changed from: private */
    public ArrayList<LocationModel> mModels;
    private TextView mRecentCount01;
    private TextView mRecentCount02;
    private ViewGroup mRecentLayout01;
    private ViewGroup mRecentLayout02;
    /* access modifiers changed from: private */
    public TextView mRecentTitle01;
    /* access modifiers changed from: private */
    public TextView mRecentTitle02;

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = View.inflate(getActivity(), R.layout.fragment_location, null);
        this.mHeaderView = View.inflate(getActivity(), R.layout.header_location, null);
        this.mHeaderView.findViewById(R.id.headerViewButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (SessionManager.getInstance().hasSession() || AppSettingManager.getInstance().isLocationInfoAgreed()) {
                    GAEvent.onGaEvent((Activity) LocationFragment.this.getActivity(), (int) R.string.gnb_location, (int) R.string.ga_ev_click, (int) R.string.gnb_location_near);
                    ParamManager.getInstance().setRecentSetModel(new LocationModel());
                    ((MainActivity) LocationFragment.this.getActivity()).onClickGnbOption();
                    return;
                }
                ((BaseActivity) LocationFragment.this.getActivity()).showConfirmDialog("\ub0b4\uc8fc\ubcc0 \uc704\uce58\uc758 \ub9e4\uc7a5 \uc815\ubcf4\ub97c \uc81c\uacf5\ubc1b\uae30\uc704\ud574 \ud604\uc7ac \uc704\uce58 \uc815\ubcf4 \uc218\uc9d1\uc5d0 \ub300\ud55c \ub3d9\uc758\ub97c \ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?", new Runnable() {
                    public void run() {
                        AppSettingManager.getInstance().setLocationInfoAgreed(true);
                        ((BaseActivity) LocationFragment.this.getActivity()).registGpsManager();
                    }
                });
            }
        });
        this.mListView = (ExpandableListView) view.findViewById(R.id.listView);
        this.mListView.addHeaderView(this.mHeaderView);
        this.mRecentTitle01 = (TextView) this.mHeaderView.findViewById(R.id.selectedLocationLabel01);
        this.mRecentTitle02 = (TextView) this.mHeaderView.findViewById(R.id.selectedLocationLabel02);
        this.mRecentCount01 = (TextView) this.mHeaderView.findViewById(R.id.selectedLocationCountLabel01);
        this.mRecentCount02 = (TextView) this.mHeaderView.findViewById(R.id.selectedLocationCountLabel02);
        this.mRecentLayout01 = (ViewGroup) this.mHeaderView.findViewById(R.id.selectedLocationLayout01);
        this.mRecentLayout02 = (ViewGroup) this.mHeaderView.findViewById(R.id.selectedLocationLayout02);
        this.mListView.setOnGroupExpandListener(new OnGroupExpandListener() {
            public void onGroupExpand(int groupPosition) {
                AppSettingManager.getInstance().setOpenLocationCode(AppSettingManager.getInstance().getOpenLocationCode() + ":" + ((LocationModel) LocationFragment.this.mModels.get(groupPosition)).getAreaGroupId());
            }
        });
        this.mListView.setOnGroupCollapseListener(new OnGroupCollapseListener() {
            public void onGroupCollapse(int groupPosition) {
                String codes = AppSettingManager.getInstance().getOpenLocationCode();
                if (codes.contains(((LocationModel) LocationFragment.this.mModels.get(groupPosition)).getAreaGroupId())) {
                    codes = codes.replace(((LocationModel) LocationFragment.this.mModels.get(groupPosition)).getAreaGroupId(), "");
                }
                AppSettingManager.getInstance().setOpenLocationCode(codes);
            }
        });
        this.mRecentLayout01.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (!LocationFragment.this.mRecentTitle01.getText().toString().equals("\uc5c6\uc74c")) {
                    GAEvent.onGaEvent(LocationFragment.this.getActivity(), R.string.gnb_location, R.string.ga_ev_click, R.string.gnb_location_confirm, ParamManager.getInstance().getModels().get(0).getAreaName());
                    ParamManager.getInstance().setRecentSetModel(ParamManager.getInstance().getModels().get(0));
                    ((MainActivity) LocationFragment.this.getActivity()).onClickGnbOption();
                }
                LocationFragment.this.setRecentlyLocationView();
            }
        });
        this.mRecentLayout02.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (!LocationFragment.this.mRecentTitle02.getText().toString().equals("\uc5c6\uc74c")) {
                    GAEvent.onGaEvent(LocationFragment.this.getActivity(), R.string.gnb_location, R.string.ga_ev_click, R.string.gnb_location_confirm, ParamManager.getInstance().getModels().get(1).getAreaName());
                    if (!ParamManager.getInstance().getModels().isEmpty()) {
                        ParamManager.getInstance().addModel(ParamManager.getInstance().getModels().get(1));
                    }
                    ((MainActivity) LocationFragment.this.getActivity()).onClickGnbOption();
                    LocationFragment.this.setRecentlyLocationView();
                }
            }
        });
        this.mModels = new ArrayList<>();
        setAdapter();
        requestLocationListApi();
        setDistanceView();
        return view;
    }

    private void setDistanceView() {
        this.mHeaderView.findViewById(R.id.distanceButton02).setOnClickListener(this.mDistanceClickListener);
        this.mHeaderView.findViewById(R.id.distanceButton03).setOnClickListener(this.mDistanceClickListener);
        this.mHeaderView.findViewById(R.id.distanceButton04).setOnClickListener(this.mDistanceClickListener);
        this.mHeaderView.findViewById(R.id.distanceButton05).setOnClickListener(this.mDistanceClickListener);
        int distance = ParamManager.getInstance().getLimitDistance();
        ((ImageView) this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.current_pin_small);
        ((ImageView) this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.current_pin_small);
        ((ImageView) this.mHeaderView.findViewById(R.id.smallPin03)).setImageResource(R.drawable.current_pin_small);
        this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(4);
        this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(4);
        this.mHeaderView.findViewById(R.id.selectedLine03).setVisibility(4);
        this.mHeaderView.findViewById(R.id.selectedLine04).setVisibility(4);
        this.mHeaderView.findViewById(R.id.selectedPin01).setVisibility(8);
        this.mHeaderView.findViewById(R.id.selectedPin02).setVisibility(8);
        this.mHeaderView.findViewById(R.id.selectedPin03).setVisibility(8);
        this.mHeaderView.findViewById(R.id.selectedPin04).setVisibility(8);
        this.mHeaderView.findViewById(R.id.selectedPin05).setVisibility(8);
        switch (distance) {
            case 500:
                this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                this.mHeaderView.findViewById(R.id.selectedPin02).setVisibility(0);
                return;
            case 1000:
                this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(0);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.select_pin_small);
                this.mHeaderView.findViewById(R.id.selectedPin03).setVisibility(0);
                return;
            case PathInterpolatorCompat.MAX_NUM_POINTS /*3000*/:
                this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(0);
                this.mHeaderView.findViewById(R.id.selectedLine03).setVisibility(0);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.select_pin_small);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin03)).setImageResource(R.drawable.select_pin_small);
                this.mHeaderView.findViewById(R.id.selectedPin04).setVisibility(0);
                return;
            case BaseImageDownloader.DEFAULT_HTTP_CONNECT_TIMEOUT /*5000*/:
                this.mHeaderView.findViewById(R.id.selectedLine01).setVisibility(0);
                this.mHeaderView.findViewById(R.id.selectedLine02).setVisibility(0);
                this.mHeaderView.findViewById(R.id.selectedLine03).setVisibility(0);
                this.mHeaderView.findViewById(R.id.selectedLine04).setVisibility(0);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin01)).setImageResource(R.drawable.select_pin_small);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin02)).setImageResource(R.drawable.select_pin_small);
                ((ImageView) this.mHeaderView.findViewById(R.id.smallPin03)).setImageResource(R.drawable.select_pin_small);
                this.mHeaderView.findViewById(R.id.selectedPin05).setVisibility(0);
                return;
            default:
                this.mHeaderView.findViewById(R.id.selectedPin01).setVisibility(0);
                return;
        }
    }

    private void setAdapter() {
        this.mAdapter = new LocationAdapter(getActivity(), this.mModels);
        this.mAdapter.setOnClickCellListener(new OnClickCell() {
            public void onClickCell(int groupIndex, int childIndex) {
                LocationModel model = ((LocationModel) LocationFragment.this.mModels.get(groupIndex)).getChildModels().get(childIndex);
                if (ParamManager.getInstance().getModels().isEmpty() || !ParamManager.getInstance().getModels().get(0).getAreaId().equals(model.getAreaId())) {
                    ParamManager.getInstance().addModel(model);
                } else {
                    ParamManager.getInstance().setRecentSetModel(model);
                }
                ((MainActivity) LocationFragment.this.getActivity()).onClickGnbOption();
                LocationFragment.this.setRecentlyLocationView();
                GAEvent.onGaEvent(LocationFragment.this.getActivity(), R.string.gnb_location, R.string.ga_ev_click, R.string.gnb_location_confirm, model.getAreaName());
            }
        });
        this.mListView.setAdapter(this.mAdapter);
    }

    /* access modifiers changed from: private */
    public void setRecentlyLocationView() {
        ArrayList<LocationModel> models = ParamManager.getInstance().getModels();
        if (models.isEmpty()) {
            this.mRecentTitle01.setText("\uc5c6\uc74c");
            this.mRecentCount01.setText("");
            this.mRecentLayout02.setVisibility(8);
            this.mHeaderView.findViewById(R.id.subLine).setVisibility(8);
        } else if (1 == models.size()) {
            this.mRecentTitle01.setText(models.get(0).getAreaName());
            this.mRecentCount01.setText(models.get(0).getCntArea());
            this.mRecentLayout02.setVisibility(8);
            this.mHeaderView.findViewById(R.id.subLine).setVisibility(8);
        } else if (2 == models.size()) {
            this.mRecentLayout02.setVisibility(0);
            this.mHeaderView.findViewById(R.id.subLine).setVisibility(0);
            this.mRecentTitle01.setText(models.get(0).getAreaName());
            this.mRecentCount01.setText(models.get(0).getCntArea());
            this.mRecentTitle02.setText(models.get(1).getAreaName());
            this.mRecentCount02.setText(models.get(1).getCntArea());
        } else {
            this.mRecentTitle01.setText("\uc5c6\uc74c");
            this.mRecentCount01.setText("");
            this.mRecentLayout02.setVisibility(8);
            this.mHeaderView.findViewById(R.id.subLine).setVisibility(8);
        }
    }

    /* access modifiers changed from: private */
    public void updateRecentlyModels() {
        ArrayList<LocationModel> models = ParamManager.getInstance().getModels();
        if (models.size() != 0) {
            for (int i = 0; i < models.size(); i++) {
                String areaId = models.get(i).getAreaId();
                if (areaId != null) {
                    for (int j = 0; j < this.mModels.size(); j++) {
                        ArrayList<LocationModel> lm = this.mModels.get(j).getChildModels();
                        if (lm != null) {
                            for (int k = 0; k < lm.size(); k++) {
                                if (areaId.equals(lm.get(k).getAreaId())) {
                                    ParamManager.getInstance().updateModel(lm.get(k));
                                }
                            }
                        }
                    }
                }
            }
            setRecentlyLocationView();
        }
    }

    /* access modifiers changed from: private */
    public void requestLocationListApi() {
        new StoreAreaListApi(getActivity()).request(new RequestHandler() {
            public void onStart() {
                if (LocationFragment.this.getActivity() != null) {
                    ((BaseActivity) LocationFragment.this.getActivity()).showLoadingDialog(true);
                }
            }

            public void onResult(Object result) {
                if (LocationFragment.this.getActivity() != null) {
                    ((BaseActivity) LocationFragment.this.getActivity()).showLoadingDialog(false);
                }
                LocationFragment.this.mModels.clear();
                LocationFragment.this.mModels.addAll(LocationFragment.this.setLocationModels(((LocationResultModel) result).getResult_list()));
                if (LocationFragment.this.mModels.size() > 0) {
                    if (!AppSettingManager.getInstance().getOpenLocationCode().isEmpty()) {
                        for (int i = 0; i < LocationFragment.this.mModels.size(); i++) {
                            if (AppSettingManager.getInstance().getOpenLocationCode().contains(((LocationModel) LocationFragment.this.mModels.get(i)).getAreaGroupId())) {
                                LocationFragment.this.mListView.expandGroup(i, true);
                            }
                        }
                    } else {
                        for (int i2 = 0; i2 < LocationFragment.this.mModels.size(); i2++) {
                            LocationFragment.this.mListView.expandGroup(i2, true);
                        }
                    }
                }
                LocationFragment.this.mAdapter.notifyDataSetChanged();
                LocationFragment.this.updateRecentlyModels();
                LocationFragment.this.mListView.smoothScrollToPosition(0, 0);
            }

            public void onFailure(Exception exception) {
                if (LocationFragment.this.getActivity() != null) {
                    ((BaseActivity) LocationFragment.this.getActivity()).showLoadingDialog(false);
                    ((BaseActivity) LocationFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            LocationFragment.this.requestLocationListApi();
                        }
                    }, null);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public ArrayList<LocationModel> setLocationModels(ArrayList<LocationModel> result) {
        ArrayList<LocationModel> models = new ArrayList<>();
        for (int i = 0; i < result.size(); i++) {
            if (result.get(i).getLevels().equals(AppEventsConstants.EVENT_PARAM_VALUE_YES)) {
                models.add(result.get(i));
            } else {
                models.get(models.size() - 1).getChildModels().add(result.get(i));
                models.get(models.size() - 1).setCntArea(String.valueOf(Integer.parseInt(models.get(models.size() - 1).getCntArea()) + Integer.parseInt(result.get(i).getCntArea())));
            }
        }
        return models;
    }

    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
        if (true == isVisibleToUser) {
            GAEvent.onGAScreenView(getActivity(), R.string.gnb_location);
        }
    }
}