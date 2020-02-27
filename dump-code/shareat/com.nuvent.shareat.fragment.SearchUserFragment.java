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
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.search.SearchApi;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.search.SearchUserModel;
import com.nuvent.shareat.model.search.SearchUserResultModel;
import com.nuvent.shareat.widget.factory.SearchUserViewFactory;
import java.net.URLEncoder;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class SearchUserFragment extends Fragment {
    /* access modifiers changed from: private */
    public ReferenceAdapter<SearchUserModel> mAdapter;
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

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_search_user, null);
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mLoadingHeaderView = View.inflate(getActivity(), R.layout.header_search_loading_user, null);
        this.mLoadingFooterView = View.inflate(getActivity(), R.layout.footer_list_loading, null);
        this.mEmptyView = (TextView) view.findViewById(R.id.emptyView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<SearchUserModel>() {
            public View getView(SearchUserModel userModel, int position) {
                return SearchUserViewFactory.createView(SearchUserFragment.this.getActivity(), userModel);
            }

            public void viewWillDisplay(View view, SearchUserModel userModel) {
            }
        });
        this.mListView.setEmptyView(view.findViewById(R.id.emptyView));
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (SearchUserFragment.this.mAdapter != null && SearchUserFragment.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !SearchUserFragment.this.mApiRequesting && SearchUserFragment.this.mLoadingFooterView.isShown()) {
                    SearchUserFragment.this.mApiRequesting = true;
                    SearchUserFragment.this.requestSearchApi(SearchUserFragment.this.mSearchText, SearchUserFragment.this.mPage);
                }
            }
        });
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) SearchUserFragment.this.getActivity()).showLoginDialog();
                    return;
                }
                Intent intent = new Intent(SearchUserFragment.this.getActivity(), InterestActivity.class);
                intent.putExtra("targetUserSno", ((SearchUserModel) SearchUserFragment.this.mAdapter.getItem(position - SearchUserFragment.this.mListView.getHeaderViewsCount())).getUserSno());
                ((BaseActivity) SearchUserFragment.this.getActivity()).pushActivity(intent);
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
        String parameter = String.format("?s_type=%s&s_word=%s&page=%d&view_cnt=%d", new Object[]{"user", searchText, Integer.valueOf(page), Integer.valueOf(20)});
        SearchApi request = new SearchApi(getActivity());
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                SearchUserResultModel model = (SearchUserResultModel) new Gson().fromJson((JsonElement) (JsonObject) result, SearchUserResultModel.class);
                if (model.getResult().equals("Y")) {
                    if (1 == SearchUserFragment.this.mPage) {
                        SearchUserFragment.this.mAdapter.clear();
                        SearchUserFragment.this.mAdapter.addAll(model.getResultList());
                        SearchUserFragment.this.mListView.setAdapter(SearchUserFragment.this.mAdapter.getAdapter());
                    } else {
                        SearchUserFragment.this.mAdapter.addAll(model.getResultList());
                    }
                    if (SearchUserFragment.this.mListView.getHeaderViewsCount() > 0) {
                        SearchUserFragment.this.mListView.removeHeaderView(SearchUserFragment.this.mLoadingHeaderView);
                    }
                    SearchUserFragment.this.mPage = SearchUserFragment.this.mPage + 1;
                    if (20 > model.getResultList().size()) {
                        SearchUserFragment.this.mListView.removeFooterView(SearchUserFragment.this.mLoadingFooterView);
                    } else {
                        SearchUserFragment.this.mLoadingFooterView.setVisibility(0);
                    }
                    if (SearchUserFragment.this.mAdapter.getCount() == 0) {
                        SearchUserFragment.this.mEmptyView.setText(SearchUserFragment.this.getResources().getString(R.string.SEARCH_FIELD_EMPTY_MSG));
                        SearchUserFragment.this.mEmptyView.setVisibility(0);
                        SearchUserFragment.this.mListView.setVisibility(8);
                    }
                    SearchUserFragment.this.mAdapter.notifyDataSetChanged();
                    return;
                }
                SearchUserFragment.this.mAdapter.clear();
                SearchUserFragment.this.mAdapter.notifyDataSetChanged();
                SearchUserFragment.this.mListView.removeHeaderView(SearchUserFragment.this.mLoadingHeaderView);
                SearchUserFragment.this.mListView.removeFooterView(SearchUserFragment.this.mLoadingFooterView);
                SearchUserFragment.this.mEmptyView.setText(SearchUserFragment.this.getResources().getString(R.string.SEARCH_FIELD_EMPTY_MSG));
                SearchUserFragment.this.mEmptyView.setVisibility(0);
                SearchUserFragment.this.mListView.setVisibility(8);
            }

            public void onFailure(Exception exception) {
                if (SearchUserFragment.this.getActivity() != null) {
                    ((BaseActivity) SearchUserFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            SearchUserFragment.this.requestSearchApi(keyword, page);
                        }
                    }, null);
                }
            }

            public void onFinish() {
                SearchUserFragment.this.mApiRequesting = false;
            }
        });
    }
}