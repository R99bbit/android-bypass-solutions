package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.app.DatePickerDialog;
import android.app.DatePickerDialog.OnDateSetListener;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.DatePicker;
import android.widget.ListView;
import android.widget.TextView;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.adapter.MyPaymentAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.MyCardListApi;
import com.nuvent.shareat.api.card.PaymentHistoryApi;
import com.nuvent.shareat.dialog.PayPeriodPickerPopup;
import com.nuvent.shareat.dialog.PayPeriodPickerPopup.PayPeriodPickerCallback;
import com.nuvent.shareat.dialog.PayTypePickerPopup;
import com.nuvent.shareat.dialog.PayTypePickerPopup.PayTypePickerCallback;
import com.nuvent.shareat.model.MyPaymentModel;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.model.user.CardModel;
import com.nuvent.shareat.model.user.CardResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CardView;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.Locale;

public class MyPaymentActivity extends MainActionBarActivity {
    private static final int VIEW_COUNT = 10;
    /* access modifiers changed from: private */
    public int DELIVERY_RESULT_CODE = 1000;
    /* access modifiers changed from: private */
    public MyPaymentAdapter mAdapter;
    /* access modifiers changed from: private */
    public boolean mApiRequesting;
    /* access modifiers changed from: private */
    public CardModel mCardModel;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public View mLoadingView;
    /* access modifiers changed from: private */
    public ArrayList<MyPaymentModel> mModels;
    /* access modifiers changed from: private */
    public int mPage = 1;
    private String orderAsc = "";
    private String orderType = "";
    /* access modifiers changed from: private */
    public String searchCard = "";
    /* access modifiers changed from: private */
    public String searchEnd = "";
    /* access modifiers changed from: private */
    public String searchStart = "";

    public void onPaymentGateButton(View view) {
        requestMyCardListApi();
    }

    public void onPaymentDateButton(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.payment_history, (int) R.string.ga_ev_click, (int) R.string.payment_history_period);
        PayPeriodPickerPopup.newInstance(new PayPeriodPickerCallback() {
            public void onPayPeriodPicker(String period, int field, int value) {
                SimpleDateFormat format = new SimpleDateFormat(StoreInstaModel.MESSAGE_CARD_TIME_FORMAT, Locale.getDefault());
                Calendar c = Calendar.getInstance();
                MyPaymentActivity.this.searchEnd = format.format(c.getTime());
                c.add(field, value);
                MyPaymentActivity.this.searchStart = format.format(c.getTime());
                MyPaymentActivity.this.mPage = 1;
                MyPaymentActivity.this.requestMyPaymentListApi();
                ((TextView) MyPaymentActivity.this.findViewById(R.id.pay_period)).setText(period);
            }
        }).show(getSupportFragmentManager(), PayPeriodPickerPopup.TAG);
    }

    public void onDirectSearchButton(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.payment_history, (int) R.string.ga_ev_click, (int) R.string.payment_history_manual);
        GregorianCalendar calendar = new GregorianCalendar();
        new DatePickerDialog(this, new OnDateSetListener() {
            public void onDateSet(DatePicker datePicker, int year, int monthOfYear, int dayOfMonth) {
                SimpleDateFormat format = new SimpleDateFormat(StoreInstaModel.MESSAGE_CARD_TIME_FORMAT, Locale.getDefault());
                Calendar c = Calendar.getInstance();
                MyPaymentActivity.this.searchEnd = format.format(c.getTime());
                c.set(1, year);
                c.set(2, monthOfYear);
                c.set(5, dayOfMonth);
                MyPaymentActivity.this.searchStart = format.format(c.getTime());
                MyPaymentActivity.this.mPage = 1;
                MyPaymentActivity.this.requestMyPaymentListApi();
            }
        }, calendar.get(1), calendar.get(2), calendar.get(5)).show();
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == -1 && requestCode == this.DELIVERY_RESULT_CODE) {
            this.mPage = 1;
            requestMyPaymentListApi();
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        String card_name;
        super.onCreate(savedInstanceState);
        GAEvent.onGAScreenView(this, R.string.payment_history);
        this.mModels = new ArrayList<>();
        setContentView(R.layout.activity_my_payment, 4);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ub098\uc758 \uacb0\uc81c\ub0b4\uc5ed");
        if (getIntent().hasExtra("cardModel")) {
            this.mCardModel = (CardModel) getIntent().getSerializableExtra("cardModel");
            this.searchCard = this.mCardModel.getCard_sno();
        }
        TextView payTypeView = (TextView) findViewById(R.id.pay_type);
        if (this.mCardModel == null) {
            card_name = getString(R.string.pay_type_all_colon);
        } else {
            card_name = this.mCardModel.getCard_name();
        }
        payTypeView.setText(card_name);
        findViewById(R.id.myCardButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent(MyPaymentActivity.this, MyCardActivity.class);
                intent.putExtra("isFadeOut", true);
                MyPaymentActivity.this.startActivity(intent);
                MyPaymentActivity.this.overridePendingTransition(R.anim.fade_in, R.anim.fade_out);
            }
        });
        this.mAdapter = new MyPaymentAdapter(this);
        this.mListView = (ListView) findViewById(R.id.list_view);
        this.mLoadingView = View.inflate(this, R.layout.footer_list_loading, null);
        this.mListView.addFooterView(View.inflate(this, R.layout.footer_my_payments, null), null, false);
        this.mListView.setAdapter(this.mAdapter);
        this.mListView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (MyPaymentActivity.this.mAdapter != null && MyPaymentActivity.this.mAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !MyPaymentActivity.this.mApiRequesting && MyPaymentActivity.this.mLoadingView.isShown()) {
                    MyPaymentActivity.this.requestMyPaymentListApi();
                }
            }
        });
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                if (view.findViewById(R.id.payment_cancle_layout).getVisibility() != 0) {
                    MyPaymentModel model = (MyPaymentModel) MyPaymentActivity.this.mModels.get(position);
                    if (true == CardView.DELIVERY.equals(model.getPay_method())) {
                        Intent intent = new Intent(MyPaymentActivity.this, PaymentDetailDeliveryActivity.class);
                        intent.putExtra("data", model);
                        MyPaymentActivity.this.animActivityForResult(intent, MyPaymentActivity.this.DELIVERY_RESULT_CODE, R.anim.slide_from_right, R.anim.slide_out_to_left);
                        return;
                    }
                    Intent intent2 = new Intent(MyPaymentActivity.this, PaymentDetailActivity.class);
                    intent2.putExtra("data", model);
                    MyPaymentActivity.this.pushActivity(intent2);
                }
            }
        });
        SimpleDateFormat format = new SimpleDateFormat(StoreInstaModel.MESSAGE_CARD_TIME_FORMAT, Locale.getDefault());
        Calendar c = Calendar.getInstance();
        this.searchEnd = format.format(c.getTime());
        c.add(4, -1);
        this.searchStart = format.format(c.getTime());
        requestMyPaymentListApi();
    }

    /* access modifiers changed from: private */
    public void requestMyPaymentListApi() {
        this.mApiRequesting = true;
        new PaymentHistoryApi(this, ApiUrl.PAMENT_HISTORY + "?page=" + this.mPage + "&view_cnt=" + 10 + "&order_type=" + this.orderType + "&order_asc=" + this.orderAsc + "&search_start=" + this.searchStart + "&search_end=" + this.searchEnd + "&search_card=" + this.searchCard).request(new RequestHandler() {
            public void onStart() {
                if (MyPaymentActivity.this.mPage == 1) {
                    MyPaymentActivity.this.showCircleDialog(true);
                }
            }

            public void onResult(Object result) {
                MyPaymentActivity.this.showCircleDialog(false);
                JsonArray objects = (JsonArray) result;
                ArrayList<MyPaymentModel> models = new ArrayList<>();
                Iterator<JsonElement> it = objects.iterator();
                while (it.hasNext()) {
                    MyPaymentModel model = (MyPaymentModel) new Gson().fromJson(it.next(), MyPaymentModel.class);
                    if (model.pay_status != 30) {
                        models.add(model);
                    }
                }
                if (MyPaymentActivity.this.mPage == 1) {
                    MyPaymentActivity.this.mModels.clear();
                    if (1 == MyPaymentActivity.this.mListView.getFooterViewsCount()) {
                        MyPaymentActivity.this.mListView.addFooterView(MyPaymentActivity.this.mLoadingView);
                    }
                }
                MyPaymentActivity.this.mModels.addAll(models);
                MyPaymentActivity.this.mAdapter.setData(MyPaymentActivity.this.mModels);
                if (10 > objects.size()) {
                    MyPaymentActivity.this.mListView.removeFooterView(MyPaymentActivity.this.mLoadingView);
                } else {
                    MyPaymentActivity.this.mPage = MyPaymentActivity.this.mPage + 1;
                }
            }

            public void onFailure(Exception exception) {
                MyPaymentActivity.this.showCircleDialog(false);
                MyPaymentActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MyPaymentActivity.this.requestMyPaymentListApi();
                    }
                });
            }

            public void onFinish() {
                MyPaymentActivity.this.mApiRequesting = false;
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestMyCardListApi() {
        new MyCardListApi(this, ApiUrl.PAMENT_LIST + String.format("?use_yn=all&ord_gubun=cash", new Object[0])).request(new RequestHandler() {
            public void onFailure(Exception exception) {
                MyPaymentActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MyPaymentActivity.this.requestMyCardListApi();
                    }
                });
            }

            public void onResult(Object result) {
                PayTypePickerPopup.newInstance(new PayTypePickerCallback() {
                    public void onPayTypePicker(CardModel card, Boolean reflush) {
                        if (card != null) {
                            MyPaymentActivity.this.mCardModel = card;
                            MyPaymentActivity.this.searchCard = card.getCard_sno();
                        } else {
                            MyPaymentActivity.this.searchCard = "";
                        }
                        MyPaymentActivity.this.searchCard = card == null ? "" : card.getCard_sno();
                        if (reflush.booleanValue()) {
                            MyPaymentActivity.this.mPage = 1;
                            MyPaymentActivity.this.requestMyPaymentListApi();
                        }
                        ((TextView) MyPaymentActivity.this.findViewById(R.id.pay_type)).setText(MyPaymentActivity.this.searchCard.isEmpty() ? MyPaymentActivity.this.getString(R.string.pay_type_all_colon) : MyPaymentActivity.this.mCardModel.getCard_name());
                    }
                }, ((CardResultModel) result).getCard_list()).show(MyPaymentActivity.this.getSupportFragmentManager(), PayTypePickerPopup.TAG);
            }

            public void onStart() {
                super.onStart();
            }
        });
    }
}