package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ListView;
import android.widget.Toast;
import com.google.gson.JsonParser;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.adapter.MyCardAdapter;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.ChangeCardNameApi;
import com.nuvent.shareat.api.card.MyCardListApi;
import com.nuvent.shareat.dialog.InputCardNameDialog;
import com.nuvent.shareat.dialog.InputCardNameDialog.onOkClickListener;
import com.nuvent.shareat.event.CardUpdateEvent;
import com.nuvent.shareat.model.user.CardModel;
import com.nuvent.shareat.model.user.CardResultModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;

public class MyCardActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public boolean isChangeCardName;
    /* access modifiers changed from: private */
    public MyCardAdapter mMyCardAdapter;

    public void onEventMainThread(CardUpdateEvent event) {
        getCardList();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_mycard, 2);
        this.isChangeCardName = getIntent().hasExtra("cardSno");
        GAEvent.onGAScreenView(this, R.string.payment_setting);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ub0b4 \uce74\ub4dc\uad00\ub9ac");
        this.mMyCardAdapter = new MyCardAdapter(this);
        ((ListView) findViewById(R.id.listView)).setAdapter(this.mMyCardAdapter);
        getCardList();
    }

    /* access modifiers changed from: private */
    public void getCardList() {
        new MyCardListApi(this, ApiUrl.PAMENT_LIST + String.format("?use_yn=&ord_gubun=cash", new Object[0])).request(new RequestHandler() {
            public void onFailure(Exception exception) {
                MyCardActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MyCardActivity.this.getCardList();
                    }
                });
            }

            public void onResult(Object result) {
                CardResultModel model = (CardResultModel) result;
                if (model.getCard_list().size() < 4) {
                    model.getCard_list().add(new CardModel());
                }
                MyCardActivity.this.mMyCardAdapter.setData(model.getCard_list());
                if (MyCardActivity.this.isChangeCardName) {
                    MyCardActivity.this.isChangeCardName = false;
                    GAEvent.onGaEvent((Activity) MyCardActivity.this, (int) R.string.payment_setting, (int) R.string.ga_ev_change, (int) R.string.payment_setting_update_card_name);
                    InputCardNameDialog dialog = new InputCardNameDialog(MyCardActivity.this);
                    dialog.setOnOkClickListener(new onOkClickListener() {
                        public void onClick(InputCardNameDialog dialog, String cardName) {
                            if (cardName == null || cardName.equals("")) {
                                MyCardActivity.this.requestChangeCardName(MyCardActivity.this.getIntent().getStringExtra("cardSno"), "");
                            } else if (cardName.length() > 6) {
                                Toast.makeText(MyCardActivity.this, R.string.payment_setting_card_rename_length_mag, 0).show();
                                return;
                            } else {
                                MyCardActivity.this.requestChangeCardName(MyCardActivity.this.getIntent().getStringExtra("cardSno"), cardName);
                            }
                            dialog.dismiss();
                        }
                    });
                    dialog.show();
                }
            }
        });
    }

    public void onClickBack(View view) {
        finish();
        if (getIntent().getBooleanExtra("isFadeOut", false)) {
            overridePendingTransition(R.anim.fade_in, R.anim.fade_out);
        }
    }

    public void onBackPressed() {
        super.onBackPressed();
        if (getIntent().getBooleanExtra("isFadeOut", false)) {
            overridePendingTransition(R.anim.fade_in, R.anim.fade_out);
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
    }

    /* access modifiers changed from: private */
    public void requestChangeCardName(final String cardSno, final String cardName) {
        ChangeCardNameApi request = new ChangeCardNameApi(this);
        request.addParam("card_sno", cardSno);
        request.addParam("card_name", cardName);
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onFailure(Exception exception) {
                MyCardActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        MyCardActivity.this.requestChangeCardName(cardSno, cardName);
                    }
                });
            }

            public void onResult(Object result) {
                if (new JsonParser().parse((String) result).getAsJsonObject().get("result").getAsString().equals("Y")) {
                    EventBus.getDefault().post(new CardUpdateEvent());
                }
            }
        });
    }
}