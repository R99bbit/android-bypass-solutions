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
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.SearchTagActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.search.SearchApi;
import com.nuvent.shareat.model.HashModel;
import com.nuvent.shareat.model.search.SearchTagResultModel;
import com.nuvent.shareat.widget.factory.SearchHashViewFactory;
import java.net.URLEncoder;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class SearchTagFragment extends Fragment {
    private static final int REQUEST_CODE_TAG_RESULT = 1;
    /* access modifiers changed from: private */
    public ReferenceAdapter<HashModel> mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public TextView mEmptyView;
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

    public void postSearch(String keyword) {
        if ((this.mSearchText == null || !this.mSearchText.equals(keyword)) && this.mEmptyView != null && this.mListView != null) {
            this.mEmptyView.setVisibility(8);
            this.mListView.setVisibility(0);
            this.mApiRequesting = true;
            this.mSearchText = keyword;
            this.mPage = 1;
            this.mLoadingFooterView.setVisibility(8);
            try {
                this.mListView.addHeaderView(this.mLoadingHeaderView);
                this.mListView.addFooterView(this.mLoadingFooterView);
            } catch (IllegalStateException e) {
                e.printStackTrace();
            }
            requestSearchApi(this.mSearchText, this.mPage);
        }
    }

    public void clearList() {
        if (this.mAdapter != null) {
            this.mAdapter.clear();
            this.mAdapter.notifyDataSetChanged();
            this.mEmptyView.setVisibility(0);
            this.mListView.setVisibility(8);
            this.mLoadingFooterView.setVisibility(8);
            this.mPage = 1;
            this.mSearchText = "";
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_search_hash, null);
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mLoadingHeaderView = View.inflate(getActivity(), R.layout.header_search_loading_hash, null);
        this.mLoadingFooterView = View.inflate(getActivity(), R.layout.footer_list_loading, null);
        this.mEmptyView = (TextView) view.findViewById(R.id.emptyView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<HashModel>() {
            public View getView(HashModel hashModel, int position) {
                return SearchHashViewFactory.createView(SearchTagFragment.this.getActivity(), hashModel);
            }

            public void viewWillDisplay(View view, HashModel hashModel) {
            }
        });
        this.mListView.setEmptyView(view.findViewById(R.id.emptyView));
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (SearchTagFragment.this.mAdapter != null && SearchTagFragment.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !SearchTagFragment.this.mApiRequesting && SearchTagFragment.this.mLoadingFooterView.isShown()) {
                    SearchTagFragment.this.mApiRequesting = true;
                    SearchTagFragment.this.requestSearchApi(SearchTagFragment.this.mSearchText, SearchTagFragment.this.mPage);
                }
            }
        });
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                Intent intent = new Intent(SearchTagFragment.this.getActivity(), SearchTagActivity.class);
                intent.putExtra("title", ((HashModel) SearchTagFragment.this.mAdapter.getItem(position)).getTagName());
                ((BaseActivity) SearchTagFragment.this.getActivity()).pushActivity(intent);
            }
        });
        this.mEmptyView.setVisibility(0);
        this.mListView.setVisibility(8);
        return view;
    }

    /* access modifiers changed from: private */
    public void requestSearchApi(final String keyword, final int page) {
        this.mApiRequesting = true;
        String searchText = keyword;
        try {
            searchText = URLEncoder.encode(URLEncoder.encode(searchText, "UTF-8"), "EUC-KR");
        } catch (Exception e) {
            e.printStackTrace();
        }
        String parameter = String.format("?s_type=%s&s_word=%s&page=%d&view_cnt=%d", new Object[]{"hashlist", searchText, Integer.valueOf(page), Integer.valueOf(20)});
        SearchApi request = new SearchApi(getActivity());
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                SearchTagResultModel model = (SearchTagResultModel) new Gson().fromJson((JsonElement) (JsonObject) result, SearchTagResultModel.class);
                if (model.getResult().equals("Y")) {
                    if (1 == SearchTagFragment.this.mPage) {
                        SearchTagFragment.this.mAdapter.clear();
                        SearchTagFragment.this.mAdapter.addAll(model.getResultList());
                        SearchTagFragment.this.mListView.setAdapter(SearchTagFragment.this.mAdapter.getAdapter());
                    } else {
                        SearchTagFragment.this.mAdapter.addAll(model.getResultList());
                    }
                    if (SearchTagFragment.this.mListView.getHeaderViewsCount() > 0) {
                        SearchTagFragment.this.mListView.removeHeaderView(SearchTagFragment.this.mLoadingHeaderView);
                    }
                    SearchTagFragment.this.mPage = SearchTagFragment.this.mPage + 1;
                    if (20 > model.getResultList().size()) {
                        SearchTagFragment.this.mListView.removeFooterView(SearchTagFragment.this.mLoadingFooterView);
                    } else {
                        SearchTagFragment.this.mLoadingFooterView.setVisibility(0);
                    }
                    if (SearchTagFragment.this.mAdapter.getCount() == 0) {
                        SearchTagFragment.this.mEmptyView.setText(SearchTagFragment.this.getResources().getString(R.string.SEARCH_FIELD_EMPTY_MSG));
                        SearchTagFragment.this.mEmptyView.setVisibility(0);
                        SearchTagFragment.this.mListView.setVisibility(8);
                    }
                    SearchTagFragment.this.mAdapter.notifyDataSetChanged();
                    return;
                }
                SearchTagFragment.this.mAdapter.clear();
                SearchTagFragment.this.mAdapter.notifyDataSetChanged();
                SearchTagFragment.this.mListView.removeHeaderView(SearchTagFragment.this.mLoadingHeaderView);
                SearchTagFragment.this.mListView.removeFooterView(SearchTagFragment.this.mLoadingFooterView);
                SearchTagFragment.this.mEmptyView.setText(SearchTagFragment.this.getResources().getString(R.string.SEARCH_FIELD_EMPTY_MSG));
                SearchTagFragment.this.mEmptyView.setVisibility(0);
                SearchTagFragment.this.mListView.setVisibility(8);
            }

            public void onFailure(Exception exception) {
                BaseActivity baseIns = (BaseActivity) SearchTagFragment.this.getActivity();
                if (baseIns != null) {
                    baseIns.handleException(exception, new Runnable() {
                        public void run() {
                            SearchTagFragment.this.requestSearchApi(keyword, page);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                SearchTagFragment.this.mApiRequesting = false;
            }
        });
    }
}