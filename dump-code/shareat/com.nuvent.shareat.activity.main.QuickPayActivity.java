package com.nuvent.shareat.activity.main;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ListView;
import com.crashlytics.android.answers.Answers;
import com.crashlytics.android.answers.SearchEvent;
import com.google.android.gms.maps.model.LatLng;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.search.QuickSearchApi;
import com.nuvent.shareat.api.search.SearchApi;
import com.nuvent.shareat.event.GpsRegistEvent;
import com.nuvent.shareat.event.RefreshQuickPayListEvent;
import com.nuvent.shareat.event.RequestAutoBranchEvent;
import com.nuvent.shareat.manager.LoplatManager;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.model.store.StoreResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.factory.SearchPartnerViewFactory;
import de.greenrobot.event.EventBus;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;
import net.xenix.android.widget.LetterSpacingTextView;

public class QuickPayActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public boolean isSearching;
    /* access modifiers changed from: private */
    public ReferenceAdapter<StoreModel> mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public View mEmptyView;
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
    private Handler mPostHandler;
    /* access modifiers changed from: private */
    public String mSearchText;
    private Date startDate = null;

    public void onEventMainThread(GpsRegistEvent event) {
        checkGpsIcon();
        if (ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            try {
                this.mLatlng = new LatLng(ShareatApp.getInstance().getGpsManager().getLatitude(), ShareatApp.getInstance().getGpsManager().getLongitude());
            } catch (Exception e) {
                e.printStackTrace();
                this.mLatlng = new LatLng(37.4986366d, 127.027021d);
            }
        }
        if (1 <= (new Date(System.currentTimeMillis()).getTime() - this.startDate.getTime()) / 60000 && ShareatApp.getInstance().getGpsManager().isGetLocation() && this.mSearchText != null && this.mSearchText.isEmpty()) {
            clearList();
            requestQuickStoreApi();
        }
    }

    public void onEventMainThread(RefreshQuickPayListEvent event) {
        if (event.getStoreModel() != null) {
            clearList();
            requestQuickStoreApi();
        }
    }

    public void onBackPressed() {
        ShareatApp.getInstance().setQuickPayClick(false);
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void postSearch(String keyword) {
        if (this.mSearchText == null || !this.mSearchText.equals(keyword)) {
            GAEvent.onGaEvent(this, R.string.quickPaySearch, R.string.ga_ev_search, R.string.quickPaySearch_Search_Store, keyword);
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
            requestSearchApi(this.mSearchText, String.valueOf(this.mLatlng.latitude), String.valueOf(this.mLatlng.longitude), this.mPage);
        }
    }

    public void clearList() {
        this.mAdapter.clear();
        this.mAdapter.notifyDataSetChanged();
        this.mListView.setVisibility(0);
        this.mPage = 1;
        this.mSearchText = "";
        this.mLoadingFooterView.setVisibility(8);
        if (this.mListView.getFooterViewsCount() == 0) {
            this.mListView.addFooterView(this.mLoadingFooterView);
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        checkGpsIcon();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    private void checkGpsIcon() {
        if (ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            ((ImageView) findViewById(R.id.locationButton)).setImageResource(R.drawable.place_market);
            findViewById(R.id.locationButton).setEnabled(false);
            return;
        }
        ((ImageView) findViewById(R.id.locationButton)).setImageResource(R.drawable.place_market_d);
        findViewById(R.id.locationButton).setEnabled(true);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_quick_pay, 153);
        this.startDate = new Date(System.currentTimeMillis());
        GAEvent.onGAScreenView(this, R.string.ga_quick_pay_search);
        findViewById(R.id.locationButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                QuickPayActivity.this.showConfirmDialog(QuickPayActivity.this.getResources().getString(R.string.GPS_PAY_MSG), new Runnable() {
                    public void run() {
                        GAEvent.onGaEvent((Activity) QuickPayActivity.this, (int) R.string.quickPaySearch, (int) R.string.ga_ev_click, (int) R.string.quickPaySearch_GPS);
                        QuickPayActivity.this.startActivity(new Intent("android.settings.LOCATION_SOURCE_SETTINGS"));
                    }
                });
            }
        });
        try {
            this.mLatlng = new LatLng(ShareatApp.getInstance().getGpsManager().getLatitude(), ShareatApp.getInstance().getGpsManager().getLongitude());
        } catch (Exception e) {
            e.printStackTrace();
            this.mLatlng = new LatLng(37.4986366d, 127.027021d);
        }
        this.mPostHandler = new Handler();
        this.mListView = (ListView) findViewById(R.id.listView);
        this.mLoadingHeaderView = View.inflate(this, R.layout.header_search_loading, null);
        this.mLoadingFooterView = View.inflate(this, R.layout.footer_list_loading, null);
        this.mEmptyView = findViewById(R.id.emptyView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<StoreModel>() {
            public View getView(StoreModel model, int position) {
                return SearchPartnerViewFactory.createView(QuickPayActivity.this, model);
            }

            public void viewWillDisplay(View view, StoreModel model) {
            }
        });
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (QuickPayActivity.this.mAdapter != null && QuickPayActivity.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !QuickPayActivity.this.mApiRequesting && QuickPayActivity.this.mLoadingFooterView.isShown()) {
                    QuickPayActivity.this.mApiRequesting = true;
                    if (QuickPayActivity.this.isSearching) {
                        QuickPayActivity.this.requestSearchApi(QuickPayActivity.this.mSearchText, String.valueOf(QuickPayActivity.this.mLatlng.latitude), String.valueOf(QuickPayActivity.this.mLatlng.longitude), QuickPayActivity.this.mPage);
                    } else {
                        QuickPayActivity.this.requestQuickStoreApi();
                    }
                }
            }
        });
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                EventBus.getDefault().post(new RequestAutoBranchEvent(2));
                Intent _intent = QuickPayActivity.this.getIntent();
                _intent.putExtra("model", (StoreModel) QuickPayActivity.this.mAdapter.getItem(position - QuickPayActivity.this.mListView.getHeaderViewsCount()));
                QuickPayActivity.this.setResult(-1, _intent);
                QuickPayActivity.this.onBackPressed();
                QuickPayActivity.this.hideKeyboard(new View(QuickPayActivity.this));
            }
        });
        ((EditText) findViewById(R.id.searchField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                QuickPayActivity.this.getKeyword();
            }
        });
        clearList();
        requestQuickStoreApi();
        checkGpsIcon();
        LetterSpacingTextView lstSelectBranchText = (LetterSpacingTextView) findViewById(R.id.select_branch_text);
        lstSelectBranchText.setCustomLetterSpacing(-2.3f);
        lstSelectBranchText.setText("\ub2e4\ub978 \ub9e4\uc7a5\uc774 \uac80\uc0c9\ub418\uc5c8\ub098\uc694? \uadfc\ucc98\ub9e4\uc7a5\uc5d0\uc11c \ub2e4\uc2dc \uc120\ud0dd\ud558\uc138\uc694.");
    }

    /* access modifiers changed from: private */
    public void getKeyword() {
        final String keyword = ((EditText) findViewById(R.id.searchField)).getText().toString().trim();
        if (keyword.isEmpty()) {
            this.isSearching = false;
            this.mPostHandler.removeMessages(0);
            clearList();
            requestQuickStoreApi();
            return;
        }
        this.isSearching = true;
        this.mPostHandler.removeMessages(0);
        this.mPostHandler = null;
        this.mPostHandler = new Handler();
        this.mPostHandler.postDelayed(new Runnable() {
            public void run() {
                QuickPayActivity.this.postSearch(keyword);
                GAEvent.onGaEvent(QuickPayActivity.this, R.string.ga_search_ev_category, R.string.ga_search_ev_action, R.string.GA_SEARCH_EV_LABEL_1, keyword);
            }
        }, 300);
    }

    /* access modifiers changed from: private */
    public void requestQuickStoreApi() {
        this.mApiRequesting = true;
        String userX = "";
        String userY = "";
        if (ShareatApp.getInstance().getGpsManager() != null && ShareatApp.getInstance().getGpsManager().isGetLocation()) {
            userX = String.valueOf(this.mLatlng.longitude);
            userY = String.valueOf(this.mLatlng.latitude);
        }
        String parameter = String.format("?user_Y=%s&user_X=%s&page=%d&view_cnt=%d", new Object[]{userY, userX, Integer.valueOf(this.mPage), Integer.valueOf(20)});
        QuickSearchApi request = new QuickSearchApi(this);
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                if (1 == QuickPayActivity.this.mPage) {
                    QuickPayActivity.this.showCircleDialog(true);
                }
            }

            public void onResult(Object result) {
                QuickPayActivity.this.showCircleDialog(false);
                StoreResultModel model = (StoreResultModel) result;
                if (model.getResult().equals("Y")) {
                    StoreModel sm = LoplatManager.getInstance(QuickPayActivity.this.getBaseContext()).getStoreModel();
                    ArrayList<StoreModel> arrSM = model.getResultList();
                    if (sm != null) {
                        int i = 0;
                        while (true) {
                            if (i >= arrSM.size()) {
                                break;
                            }
                            StoreModel quickSM = arrSM.get(i);
                            if (true == quickSM.partnerSno.equals(sm.partnerSno)) {
                                sm.listImg = quickSM.getListImg();
                                sm.distance = quickSM.getDistance();
                                sm.categoryName = quickSM.getCategoryName();
                                sm.dongName = quickSM.getDongName();
                                arrSM.remove(i);
                                break;
                            }
                            i++;
                        }
                        arrSM.add(0, sm);
                    }
                    if (1 == QuickPayActivity.this.mPage) {
                        QuickPayActivity.this.mAdapter.clear();
                        QuickPayActivity.this.mAdapter.addAll(arrSM);
                        QuickPayActivity.this.mListView.setAdapter(QuickPayActivity.this.mAdapter.getAdapter());
                    } else {
                        QuickPayActivity.this.mAdapter.addAll(arrSM);
                    }
                    if (QuickPayActivity.this.mListView.getHeaderViewsCount() > 0) {
                        QuickPayActivity.this.mListView.removeHeaderView(QuickPayActivity.this.mLoadingHeaderView);
                    }
                    QuickPayActivity.this.mPage = QuickPayActivity.this.mPage + 1;
                    if (20 > model.getResultList().size()) {
                        QuickPayActivity.this.mListView.removeFooterView(QuickPayActivity.this.mLoadingFooterView);
                    } else {
                        QuickPayActivity.this.mLoadingFooterView.setVisibility(0);
                    }
                    QuickPayActivity.this.mAdapter.notifyDataSetChanged();
                }
            }

            public void onFailure(Exception exception) {
                QuickPayActivity.this.showCircleDialog(false);
                QuickPayActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        QuickPayActivity.this.requestQuickStoreApi();
                    }
                }, null);
            }

            public void onFinish() {
                QuickPayActivity.this.showCircleDialog(false);
                QuickPayActivity.this.mApiRequesting = false;
            }
        });
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
        SearchApi request = new SearchApi(this);
        request.addGetParam(parameter);
        final String str = keyword;
        final String str2 = userY;
        final String str3 = userX;
        final int i = page;
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                StoreResultModel model = (StoreResultModel) new Gson().fromJson((JsonElement) (JsonObject) result, StoreResultModel.class);
                if (model.getResult().equals("Y")) {
                    if (1 == QuickPayActivity.this.mPage) {
                        QuickPayActivity.this.mAdapter.clear();
                        QuickPayActivity.this.mAdapter.addAll(model.getResultList());
                        QuickPayActivity.this.mListView.setAdapter(QuickPayActivity.this.mAdapter.getAdapter());
                    } else {
                        QuickPayActivity.this.mAdapter.addAll(model.getResultList());
                    }
                    if (QuickPayActivity.this.mListView.getHeaderViewsCount() > 0) {
                        QuickPayActivity.this.mListView.removeHeaderView(QuickPayActivity.this.mLoadingHeaderView);
                    }
                    QuickPayActivity.this.mPage = QuickPayActivity.this.mPage + 1;
                    if (20 > model.getResultList().size()) {
                        QuickPayActivity.this.mListView.removeFooterView(QuickPayActivity.this.mLoadingFooterView);
                    } else {
                        QuickPayActivity.this.mLoadingFooterView.setVisibility(0);
                    }
                    if (QuickPayActivity.this.mAdapter.getCount() == 0) {
                        QuickPayActivity.this.mEmptyView.setVisibility(0);
                        QuickPayActivity.this.mListView.setVisibility(8);
                    }
                    QuickPayActivity.this.mAdapter.notifyDataSetChanged();
                    return;
                }
                QuickPayActivity.this.mAdapter.clear();
                QuickPayActivity.this.mAdapter.notifyDataSetChanged();
                QuickPayActivity.this.mListView.removeHeaderView(QuickPayActivity.this.mLoadingHeaderView);
                QuickPayActivity.this.mListView.removeFooterView(QuickPayActivity.this.mLoadingFooterView);
                QuickPayActivity.this.mEmptyView.setVisibility(0);
                QuickPayActivity.this.mListView.setVisibility(8);
            }

            public void onFailure(Exception exception) {
                QuickPayActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        QuickPayActivity.this.requestSearchApi(str, str2, str3, i);
                    }
                }, null);
            }

            public void onFinish() {
                Answers.getInstance().logSearch(new SearchEvent().putQuery(str));
                QuickPayActivity.this.mApiRequesting = false;
            }
        });
    }
}