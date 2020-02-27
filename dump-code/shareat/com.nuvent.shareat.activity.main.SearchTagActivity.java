package com.nuvent.shareat.activity.main;

import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.ListView;
import android.widget.TextView;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.search.SearchApi;
import com.nuvent.shareat.model.search.TagModel;
import com.nuvent.shareat.model.search.TagResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.factory.TagResultViewFactory;
import java.net.URLEncoder;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class SearchTagActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public ReferenceAdapter<TagModel> mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public Typeface mBoldFont;
    /* access modifiers changed from: private */
    public TextView mEmptyView;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public View mLoadingView;
    /* access modifiers changed from: private */
    public int mPage = 1;
    /* access modifiers changed from: private */
    public String mTagName;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tag_search, 2);
        GAEvent.onGAScreenView(this, R.string.ga_search_tag_result);
        this.mBoldFont = Typeface.createFromAsset(getAssets(), "NanumBarunGothicBold.ttf");
        this.mTagName = getIntent().getStringExtra("title");
        setTitle(this.mTagName);
        showFavoriteButton(false);
        this.mEmptyView = (TextView) findViewById(R.id.emptyView);
        this.mLoadingView = View.inflate(this, R.layout.footer_list_loading, null);
        this.mListView = (ListView) findViewById(R.id.listView);
        this.mListView.addFooterView(this.mLoadingView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<TagModel>() {
            public View getView(TagModel model, int position) {
                return TagResultViewFactory.createView(SearchTagActivity.this, model, SearchTagActivity.this.mBoldFont, SearchTagActivity.this.mTagName);
            }

            public void viewWillDisplay(View view, TagModel model) {
            }
        });
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (SearchTagActivity.this.mAdapter != null && SearchTagActivity.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !SearchTagActivity.this.mApiRequesting && SearchTagActivity.this.mLoadingView.isShown()) {
                    SearchTagActivity.this.mApiRequesting = true;
                    SearchTagActivity.this.requestSearchApi(SearchTagActivity.this.mTagName);
                }
            }
        });
        requestSearchApi(this.mTagName);
    }

    /* access modifiers changed from: private */
    public void requestSearchApi(final String tagName) {
        this.mApiRequesting = true;
        String tag = tagName;
        try {
            tag = URLEncoder.encode(URLEncoder.encode(tag, "UTF-8"), "EUC-KR");
        } catch (Exception e) {
            e.printStackTrace();
        }
        String parameter = String.format("?s_type=%s&s_word=%s&page=%d&view_cnt=%d", new Object[]{"hashresult", tag, Integer.valueOf(this.mPage), Integer.valueOf(20)});
        SearchApi request = new SearchApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                TagResultModel model = (TagResultModel) new Gson().fromJson((JsonElement) (JsonObject) result, TagResultModel.class);
                if (model.getResult().equals("Y")) {
                    if (1 == SearchTagActivity.this.mPage) {
                        SearchTagActivity.this.mAdapter.clear();
                        SearchTagActivity.this.mAdapter.addAll(model.getResult_list());
                        SearchTagActivity.this.mListView.setAdapter(SearchTagActivity.this.mAdapter.getAdapter());
                    } else {
                        SearchTagActivity.this.mAdapter.addAll(model.getResult_list());
                    }
                    if (20 > model.getResult_list().size()) {
                        SearchTagActivity.this.mListView.removeFooterView(SearchTagActivity.this.mLoadingView);
                    } else {
                        SearchTagActivity.this.mPage = SearchTagActivity.this.mPage + 1;
                    }
                    if (SearchTagActivity.this.mAdapter.getCount() == 0) {
                        SearchTagActivity.this.mEmptyView.setVisibility(0);
                        SearchTagActivity.this.mListView.setVisibility(8);
                    }
                    SearchTagActivity.this.mAdapter.notifyDataSetChanged();
                    return;
                }
                SearchTagActivity.this.mAdapter.clear();
                SearchTagActivity.this.mAdapter.notifyDataSetChanged();
                SearchTagActivity.this.mListView.removeFooterView(SearchTagActivity.this.mLoadingView);
                SearchTagActivity.this.mEmptyView.setVisibility(0);
                SearchTagActivity.this.mListView.setVisibility(8);
            }

            public void onFailure(Exception exception) {
                SearchTagActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        SearchTagActivity.this.requestSearchApi(tagName);
                    }
                });
            }

            public void onFinish() {
                SearchTagActivity.this.mApiRequesting = false;
            }
        });
    }
}