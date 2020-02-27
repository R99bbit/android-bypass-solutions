package com.nuvent.shareat.fragment;

import android.content.Intent;
import android.os.Bundle;
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
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.SearchEvent;
import com.google.android.gms.maps.model.LatLng;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.search.SearchApi;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.store.StoreResultModel;
import com.nuvent.shareat.widget.factory.SearchPartnerViewFactory;
import java.net.URLEncoder;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class SearchPartnerFragment extends Fragment {
    /* access modifiers changed from: private */
    public ReferenceAdapter<StoreModel> mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public TextView mEmptyView;
    /* access modifiers changed from: private */
    public LatLng mLatlng;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public View mLoadingFooterView;
    /* access modifiers changed from: private */
    public View mLoadingHeaderView;
    /* access modifiers changed from: private */
    public int mPage = 1;
    /* access modifiers changed from: private */
    public String mSearchText;

    public void postSearch(String keyword, LatLng latLng) {
        if ((this.mSearchText == null || !this.mSearchText.equals(keyword)) && this.mEmptyView != null && this.mListView != null) {
            this.mEmptyView.setVisibility(8);
            this.mListView.setVisibility(0);
            this.mApiRequesting = true;
            this.mSearchText = keyword;
            this.mPage = 1;
            this.mLatlng = latLng;
            this.mLoadingFooterView.setVisibility(8);
            try {
                this.mListView.addHeaderView(this.mLoadingHeaderView);
                this.mListView.addFooterView(this.mLoadingFooterView);
            } catch (IllegalStateException e) {
                e.printStackTrace();
            }
            requestSearchApi(this.mSearchText, String.valueOf(this.mLatlng.latitude), String.valueOf(this.mLatlng.longitude), this.mPage);
        }
    }

    public void clearList() {
        if (this.mAdapter == null) {
            setAdapter();
            return;
        }
        this.mAdapter.clear();
        this.mAdapter.notifyDataSetChanged();
        if (this.mEmptyView != null) {
            this.mEmptyView.setVisibility(0);
        }
        this.mListView.setVisibility(8);
        this.mLoadingFooterView.setVisibility(8);
        this.mPage = 1;
        this.mSearchText = "";
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_search_partner, null);
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mLoadingHeaderView = View.inflate(getActivity(), R.layout.header_search_loading, null);
        this.mLoadingFooterView = View.inflate(getActivity(), R.layout.footer_list_loading, null);
        this.mEmptyView = (TextView) view.findViewById(R.id.emptyView);
        setAdapter();
        this.mEmptyView.setVisibility(0);
        this.mListView.setVisibility(8);
        return view;
    }

    private void setAdapter() {
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<StoreModel>() {
            public View getView(StoreModel model, int position) {
                return SearchPartnerViewFactory.createView(SearchPartnerFragment.this.getActivity(), model);
            }

            public void viewWillDisplay(View view, StoreModel model) {
            }
        });
        try {
            this.mListView.setAdapter(this.mAdapter.getAdapter());
        } catch (Exception e) {
            e.printStackTrace();
            if (getActivity() != null) {
                getActivity().finish();
            }
        }
        if (this.mListView != null) {
            this.mListView.setOnScrollListener(new OnScrollListener() {
                public void onScrollStateChanged(AbsListView view, int scrollState) {
                }

                public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                    if (SearchPartnerFragment.this.mAdapter != null && SearchPartnerFragment.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !SearchPartnerFragment.this.mApiRequesting && SearchPartnerFragment.this.mLoadingFooterView.isShown()) {
                        SearchPartnerFragment.this.mApiRequesting = true;
                        SearchPartnerFragment.this.requestSearchApi(SearchPartnerFragment.this.mSearchText, String.valueOf(SearchPartnerFragment.this.mLatlng.latitude), String.valueOf(SearchPartnerFragment.this.mLatlng.longitude), SearchPartnerFragment.this.mPage);
                    }
                }
            });
            this.mListView.setOnItemClickListener(new OnItemClickListener() {
                public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                    int position2 = position - SearchPartnerFragment.this.mListView.getHeaderViewsCount();
                    ReferenceAdapter access$000 = SearchPartnerFragment.this.mAdapter;
                    if (position2 == -1) {
                        position2 = 0;
                    }
                    Intent intent = new Intent(SearchPartnerFragment.this.getActivity(), StoreDetailActivity.class);
                    intent.putExtra("model", (StoreModel) access$000.getItem(position2));
                    ((BaseActivity) SearchPartnerFragment.this.getActivity()).pushActivity(intent);
                    ((BaseActivity) SearchPartnerFragment.this.getActivity()).hideKeyboard(new View(SearchPartnerFragment.this.getActivity()));
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void requestSearchApi(String keyword, String userY, String userX, int page) {
        this.mApiRequesting = true;
        String searchText = keyword;
        try {
            searchText = URLEncoder.encode(URLEncoder.encode(searchText, "UTF-8"), "EUC-KR");
        } catch (Exception e) {
            e.printStackTrace();
        }
        String parameter = String.format("?s_type=partner&s_word=%s&user_X=%s&user_Y=%s&page=%d&view_cnt=%d", new Object[]{searchText, userX, userY, Integer.valueOf(page), Integer.valueOf(20)});
        SearchApi request = new SearchApi(getActivity());
        request.addGetParam(parameter);
        final String str = keyword;
        final String str2 = userY;
        final String str3 = userX;
        final int i = page;
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreResultModel model = (StoreResultModel) new Gson().fromJson((JsonElement) (JsonObject) result, StoreResultModel.class);
                if (model.getResult().equals("Y")) {
                    if (1 == SearchPartnerFragment.this.mPage) {
                        SearchPartnerFragment.this.mAdapter.clear();
                        SearchPartnerFragment.this.mAdapter.addAll(model.getResultList());
                        SearchPartnerFragment.this.mListView.setAdapter(SearchPartnerFragment.this.mAdapter.getAdapter());
                    } else {
                        SearchPartnerFragment.this.mAdapter.addAll(model.getResultList());
                    }
                    if (SearchPartnerFragment.this.mListView.getHeaderViewsCount() > 0) {
                        SearchPartnerFragment.this.mListView.removeHeaderView(SearchPartnerFragment.this.mLoadingHeaderView);
                    }
                    SearchPartnerFragment.this.mPage = SearchPartnerFragment.this.mPage + 1;
                    if (20 > model.getResultList().size()) {
                        SearchPartnerFragment.this.mListView.removeFooterView(SearchPartnerFragment.this.mLoadingFooterView);
                    } else {
                        SearchPartnerFragment.this.mLoadingFooterView.setVisibility(0);
                    }
                    if (SearchPartnerFragment.this.mAdapter.getCount() == 0) {
                        SearchPartnerFragment.this.mEmptyView.setText(SearchPartnerFragment.this.getResources().getString(R.string.SEARCH_FIELD_EMPTY_MSG));
                        SearchPartnerFragment.this.mEmptyView.setVisibility(0);
                        SearchPartnerFragment.this.mListView.setVisibility(8);
                    }
                    SearchPartnerFragment.this.mAdapter.notifyDataSetChanged();
                    return;
                }
                SearchPartnerFragment.this.mAdapter.clear();
                SearchPartnerFragment.this.mAdapter.notifyDataSetChanged();
                SearchPartnerFragment.this.mListView.removeHeaderView(SearchPartnerFragment.this.mLoadingHeaderView);
                SearchPartnerFragment.this.mListView.removeFooterView(SearchPartnerFragment.this.mLoadingFooterView);
                SearchPartnerFragment.this.mEmptyView.setText(SearchPartnerFragment.this.getResources().getString(R.string.SEARCH_FIELD_EMPTY_MSG));
                SearchPartnerFragment.this.mEmptyView.setVisibility(0);
                SearchPartnerFragment.this.mListView.setVisibility(8);
            }

            public void onFailure(Exception exception) {
                if (SearchPartnerFragment.this.getActivity() != null) {
                    ((BaseActivity) SearchPartnerFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            SearchPartnerFragment.this.requestSearchApi(str, str2, str3, i);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                Answers.getInstance().logSearch(new SearchEvent().putQuery(str));
                SearchPartnerFragment.this.mApiRequesting = false;
            }
        });
    }
}