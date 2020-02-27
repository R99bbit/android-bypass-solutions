package com.nuvent.shareat.fragment;

import android.app.Activity;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ExpandableListView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.MainActivity;
import com.nuvent.shareat.adapter.CategoryAdapter;
import com.nuvent.shareat.adapter.CategoryAdapter.OnClickCell;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreCategoryListApi;
import com.nuvent.shareat.manager.app.ParamManager;
import com.nuvent.shareat.model.store.CategoryModel;
import com.nuvent.shareat.model.store.CategoryResultModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;

public class CategoryFragment extends Fragment implements OnClickListener {
    /* access modifiers changed from: private */
    public CategoryAdapter mAdapter;
    /* access modifiers changed from: private */
    public View mHeaderView;
    private ExpandableListView mListView;
    /* access modifiers changed from: private */
    public ArrayList<CategoryModel> mModels;
    /* access modifiers changed from: private */
    public int mSelectedSortType;
    private OnClickListener sortButtonClickListener = new OnClickListener() {
        public void onClick(View v) {
            switch (v.getId()) {
                case R.id.sortDistanceCheck /*2131297325*/:
                    CategoryFragment.this.mSelectedSortType = 1;
                    break;
                case R.id.sortPopularCheck /*2131297326*/:
                    CategoryFragment.this.mSelectedSortType = 5;
                    break;
                case R.id.sortTimeCheck /*2131297327*/:
                    CategoryFragment.this.mSelectedSortType = 0;
                    break;
            }
            CategoryFragment.this.setSortButton(CategoryFragment.this.mSelectedSortType);
        }
    };

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = View.inflate(getActivity(), R.layout.fragment_category, null);
        this.mModels = new ArrayList<>();
        this.mHeaderView = View.inflate(getActivity(), R.layout.header_category, null);
        this.mHeaderView.findViewById(R.id.sortTimeCheck).setOnClickListener(this.sortButtonClickListener);
        this.mHeaderView.findViewById(R.id.sortDistanceCheck).setOnClickListener(this.sortButtonClickListener);
        this.mHeaderView.findViewById(R.id.sortPopularCheck).setOnClickListener(this.sortButtonClickListener);
        this.mHeaderView.findViewById(R.id.allCheck).setOnClickListener(this);
        view.findViewById(R.id.confirmButton).setOnClickListener(this);
        this.mListView = (ExpandableListView) view.findViewById(R.id.listView);
        this.mListView.addHeaderView(this.mHeaderView);
        setAdapter();
        requestCategoryListApi();
        return view;
    }

    public void setSortButton(int sortType) {
        if (this.mHeaderView != null) {
            this.mSelectedSortType = sortType;
            this.mHeaderView.findViewById(R.id.sortTimeCheck).setSelected(false);
            this.mHeaderView.findViewById(R.id.sortDistanceCheck).setSelected(false);
            this.mHeaderView.findViewById(R.id.sortPopularCheck).setSelected(false);
            switch (sortType) {
                case 0:
                    GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.gnb_category, (int) R.string.ga_ev_click, (int) R.string.gnb_category_sort_time);
                    this.mHeaderView.findViewById(R.id.sortTimeCheck).setSelected(true);
                    return;
                case 1:
                    GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.gnb_category, (int) R.string.ga_ev_click, (int) R.string.gnb_category_sort_distance);
                    this.mHeaderView.findViewById(R.id.sortDistanceCheck).setSelected(true);
                    return;
                case 5:
                    GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.gnb_category, (int) R.string.ga_ev_click, (int) R.string.gnb_category_sort_rank);
                    this.mHeaderView.findViewById(R.id.sortPopularCheck).setSelected(true);
                    return;
                default:
                    return;
            }
        }
    }

    public void setCategoryCheck() {
        if (this.mHeaderView != null) {
            clearCheck();
            if (ParamManager.getInstance().getCategory().isEmpty()) {
                this.mHeaderView.findViewById(R.id.allCheck).performClick();
                return;
            }
            String[] categoryId = ParamManager.getInstance().getCategory().split(",");
            for (int i = 0; i < this.mModels.size(); i++) {
                for (int j = 0; j < this.mModels.get(i).getChildModels().size(); j++) {
                    for (String equals : categoryId) {
                        if (this.mModels.get(i).getChildModels().get(j).getCategoryId().equals(equals)) {
                            this.mModels.get(i).getChildModels().get(j).setSelected(true);
                        }
                    }
                }
            }
            this.mAdapter.notifyDataSetChanged();
        }
    }

    private void setAdapter() {
        this.mAdapter = new CategoryAdapter(getActivity(), this.mModels);
        this.mAdapter.setOnClickCellListener(new OnClickCell() {
            public void onCheckItem(int groupPosition, int childPosition, boolean isChecked) {
                ((CategoryModel) CategoryFragment.this.mModels.get(groupPosition)).getChildModels().get(childPosition).setSelected(isChecked);
                CategoryFragment.this.mAdapter.notifyDataSetChanged();
                CategoryFragment.this.mHeaderView.findViewById(R.id.allCheck).setSelected(CategoryFragment.this.isAllCheck());
            }
        });
        this.mListView.setAdapter(this.mAdapter);
    }

    /* access modifiers changed from: private */
    public void expandableListView() {
        for (int i = 0; i < this.mModels.size(); i++) {
            if (!this.mListView.isGroupExpanded(i)) {
                this.mListView.expandGroup(i);
            }
        }
    }

    /* access modifiers changed from: private */
    public void requestCategoryListApi() {
        new StoreCategoryListApi(getActivity()).request(new RequestHandler() {
            public void onStart() {
                if (((BaseActivity) CategoryFragment.this.getActivity()) != null) {
                    ((BaseActivity) CategoryFragment.this.getActivity()).showLoadingDialog(true);
                }
            }

            public void onResult(Object result) {
                if (((BaseActivity) CategoryFragment.this.getActivity()) != null) {
                    ((BaseActivity) CategoryFragment.this.getActivity()).showLoadingDialog(false);
                    CategoryFragment.this.mModels.clear();
                    CategoryFragment.this.mModels.addAll(CategoryFragment.this.setCategotyModels(((CategoryResultModel) result).getResult_list()));
                    CategoryFragment.this.expandableListView();
                    CategoryFragment.this.mAdapter.notifyDataSetChanged();
                }
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) CategoryFragment.this.getActivity()) != null) {
                    ((BaseActivity) CategoryFragment.this.getActivity()).showLoadingDialog(false);
                    ((BaseActivity) CategoryFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            CategoryFragment.this.requestCategoryListApi();
                        }
                    }, null);
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public ArrayList<CategoryModel> setCategotyModels(ArrayList<CategoryModel> result) {
        ArrayList<CategoryModel> models = new ArrayList<>();
        for (int i = 0; i < result.size(); i++) {
            if (result.get(i).getLevels().equals(AppEventsConstants.EVENT_PARAM_VALUE_YES)) {
                models.add(result.get(i));
            } else {
                models.get(models.size() - 1).getChildModels().add(result.get(i));
            }
        }
        return models;
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.allCheck /*2131296307*/:
                v.setSelected(!v.isSelected());
                setAllCheck(v.isSelected());
                this.mAdapter.notifyDataSetChanged();
                return;
            case R.id.confirmButton /*2131296504*/:
                GAEvent.onGaEvent((Activity) getActivity(), (int) R.string.gnb_category, (int) R.string.ga_ev_ok, (int) R.string.gnb_category_confirm);
                ParamManager.getInstance().setCategory(getCheckValue());
                ParamManager.getInstance().setSortType(this.mSelectedSortType);
                ((MainActivity) getActivity()).onClickGnbOption();
                return;
            default:
                return;
        }
    }

    private void setAllCheck(boolean isAllCheck) {
        for (int i = 0; i < this.mModels.size(); i++) {
            for (int j = 0; j < this.mModels.get(i).getChildModels().size(); j++) {
                this.mModels.get(i).getChildModels().get(j).setSelected(isAllCheck);
            }
        }
    }

    /* access modifiers changed from: private */
    public boolean isAllCheck() {
        boolean reValue = true;
        for (int i = 0; i < this.mModels.size(); i++) {
            int j = 0;
            while (true) {
                if (j >= this.mModels.get(i).getChildModels().size()) {
                    break;
                } else if (!this.mModels.get(i).getChildModels().get(j).isSelected().booleanValue()) {
                    reValue = false;
                    break;
                } else {
                    j++;
                }
            }
        }
        return reValue;
    }

    private String getCheckValue() {
        String reValue = "";
        if (!this.mHeaderView.findViewById(R.id.allCheck).isSelected()) {
            for (int i = 0; i < this.mModels.size(); i++) {
                for (int j = 0; j < this.mModels.get(i).getChildModels().size(); j++) {
                    if (this.mModels.get(i).getChildModels().get(j).isSelected().booleanValue()) {
                        reValue = reValue + this.mModels.get(i).getChildModels().get(j).getCategoryId() + ",";
                    }
                }
            }
        }
        return reValue;
    }

    private void clearCheck() {
        if (this.mHeaderView != null) {
            this.mHeaderView.findViewById(R.id.allCheck).setSelected(false);
            for (int i = 0; i < this.mModels.size(); i++) {
                for (int j = 0; j < this.mModels.get(i).getChildModels().size(); j++) {
                    this.mModels.get(i).getChildModels().get(j).setSelected(false);
                }
            }
        }
    }

    public void onResume() {
        super.onResume();
    }

    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
        if (true == isVisibleToUser) {
            GAEvent.onGAScreenView(getActivity(), R.string.gnb_category);
        }
    }
}