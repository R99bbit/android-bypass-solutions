package com.nuvent.shareat.activity.main;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.support.v4.widget.SwipeRefreshLayout;
import android.support.v4.widget.SwipeRefreshLayout.OnRefreshListener;
import android.view.View;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.ListView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.adapter.store.StoreListAdapter;
import com.nuvent.shareat.adapter.store.StoreListAdapter.OnClickStoreItem;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreListApi;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.store.StoreResultModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;

public class StoreListActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public StoreListAdapter mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public View mEmptyView;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public View mLoadingView;
    /* access modifiers changed from: private */
    public ArrayList<StoreModel> mModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public int mPage = 1;
    private Bundle mParams;
    /* access modifiers changed from: private */
    public SwipeRefreshLayout mRefreshLayout;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_store_list, 2);
        showFavoriteButton(false);
        this.mListView = (ListView) findViewById(R.id.listView);
        this.mLoadingView = View.inflate(this, R.layout.footer_list_loading, null);
        this.mEmptyView = findViewById(R.id.emptyView);
        this.mRefreshLayout = (SwipeRefreshLayout) findViewById(R.id.swipeRefreshLayout);
        this.mRefreshLayout.setOnRefreshListener(new OnRefreshListener() {
            public void onRefresh() {
                StoreListActivity.this.mPage = 1;
                StoreListActivity.this.postStoreApi();
            }
        });
        this.mRefreshLayout.setColorSchemeResources(R.color.main_list_pay_cnt_color, R.color.green, R.color.blue, R.color.yellow);
        setAdapter();
        postStoreApi();
    }

    private void setAdapter() {
        this.mAdapter = new StoreListAdapter(this, Typeface.createFromAsset(getAssets(), "NanumBarunGothicBold.ttf"), this.mModels);
        this.mAdapter.setOnClickStoreItemListener(new OnClickStoreItem() {
            public void onClickUser(StoreModel model) {
                if (!SessionManager.getInstance().hasSession()) {
                    StoreListActivity.this.showLoginDialog();
                } else if (model.getHeadListKind() != null && !model.getHeadListKind().equals("M") && !model.getLastName().equals("\ube44\uacf5\uac1c")) {
                    Intent intent = new Intent(StoreListActivity.this, InterestActivity.class);
                    if (ShareatApp.getInstance().getUserNum() == null || !ShareatApp.getInstance().getUserNum().equals(model.getLastuserSno())) {
                        intent.putExtra("targetUserSno", model.getLastuserSno());
                    }
                    if (model.getHeadListKind().equals("S")) {
                        intent.putExtra("isReview", "");
                    }
                    StoreListActivity.this.pushActivity(intent);
                    GAEvent.onGaEvent((Activity) StoreListActivity.this, (int) R.string.ga_storelist, (int) R.string.ga_ev_click, (int) R.string.ga_storelist_profile);
                } else if (model.getHeadListKind().equals("M")) {
                    Intent intent2 = new Intent(StoreListActivity.this, StoreDetailActivity.class);
                    intent2.putExtra("model", model);
                    StoreListActivity.this.pushActivity(intent2);
                }
            }

            public void onClickStore(StoreModel model) {
                Intent intent = new Intent(StoreListActivity.this, StoreDetailActivity.class);
                intent.putExtra("model", model);
                StoreListActivity.this.pushActivity(intent);
            }
        });
        this.mListView.setAdapter(this.mAdapter);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                StoreListActivity.this.mRefreshLayout.setEnabled(StoreListActivity.this.getScrollY() <= 0);
                if (StoreListActivity.this.mModels != null && StoreListActivity.this.mModels.size() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !StoreListActivity.this.mApiRequesting && StoreListActivity.this.mLoadingView.isShown()) {
                    StoreListActivity.this.postStoreApi();
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public int getScrollY() {
        View c = this.mListView.getChildAt(0);
        if (c == null) {
            return 0;
        }
        return (-c.getTop()) + (c.getHeight() * this.mListView.getFirstVisiblePosition()) + 0;
    }

    private String getQueryString(Bundle bundle) {
        String parameter = "?";
        for (String key : bundle.keySet()) {
            if (!key.equals("title")) {
                parameter = parameter + key + "=" + bundle.getString(key) + "&";
            }
        }
        if (parameter.endsWith("&")) {
            return parameter.substring(0, parameter.length() - 1);
        }
        return parameter;
    }

    /* access modifiers changed from: private */
    public void postStoreApi() {
        this.mParams = getIntent().getBundleExtra(CustomSchemeManager.EXTRA_INTENT_PARAMETER);
        if (this.mParams == null) {
            finish();
            return;
        }
        setTitle(this.mParams.getString("title", ""));
        if (this.mParams.getString("user_X") != null && this.mParams.getString("user_X").equals("$user_X")) {
            double lat = 37.4986366d;
            double lng = 127.027021d;
            try {
                if (ShareatApp.getInstance().getGpsManager() != null) {
                    lat = ShareatApp.getInstance().getGpsManager().getLatitude();
                    lng = ShareatApp.getInstance().getGpsManager().getLongitude();
                }
                this.mParams.putString("user_X", String.valueOf(lng));
                this.mParams.putString("user_Y", String.valueOf(lat));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        this.mParams.putString("page", String.valueOf(this.mPage));
        requestStoreListApi(getQueryString(this.mParams), Integer.parseInt(this.mParams.getString("view_cnt", "10")));
    }

    /* access modifiers changed from: private */
    public void requestStoreListApi(final String parameter, final int viewCount) {
        this.mApiRequesting = true;
        StoreListApi request = new StoreListApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreResultModel resultModel = (StoreResultModel) result;
                if (StoreListActivity.this.mPage == 1) {
                    StoreListActivity.this.mModels.clear();
                    StoreListActivity.this.mModels.addAll(resultModel.getResultList());
                    StoreListActivity.this.mAdapter.setHeadPeriodText(resultModel.getHead_period_text());
                    if (StoreListActivity.this.mListView.getFooterViewsCount() == 0) {
                        StoreListActivity.this.mListView.addFooterView(StoreListActivity.this.mLoadingView);
                    }
                    StoreListActivity.this.mListView.setAdapter(StoreListActivity.this.mAdapter);
                } else if (resultModel.getResultList().size() > 0) {
                    StoreListActivity.this.mModels.addAll(resultModel.getResultList());
                    StoreListActivity.this.mAdapter.notifyDataSetChanged();
                }
                if (StoreListActivity.this.mModels.size() == 0) {
                    StoreListActivity.this.mEmptyView.setVisibility(0);
                } else {
                    StoreListActivity.this.mEmptyView.setVisibility(8);
                }
                if (viewCount > resultModel.getResultList().size()) {
                    StoreListActivity.this.mListView.removeFooterView(StoreListActivity.this.mLoadingView);
                } else {
                    StoreListActivity.this.mPage = StoreListActivity.this.mPage + 1;
                }
                StoreListActivity.this.mRefreshLayout.setRefreshing(false);
            }

            public void onFailure(Exception exception) {
                StoreListActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        StoreListActivity.this.requestStoreListApi(parameter, viewCount);
                    }
                }, null);
            }

            public void onFinish() {
                StoreListActivity.this.mApiRequesting = false;
            }
        });
    }
}