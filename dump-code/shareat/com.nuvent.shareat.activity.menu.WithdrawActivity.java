package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.animation.AnimationUtils;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.WithdrawApi;
import com.nuvent.shareat.api.common.WithdrawInfoApi;
import com.nuvent.shareat.dialog.InputConfirmDialog;
import com.nuvent.shareat.dialog.InputConfirmDialog.onOkClickListener;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.WithdrawInfoModel;
import com.nuvent.shareat.model.WithdrawReasonModel;
import com.nuvent.shareat.model.WithdrawResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.factory.WithdrawViewFactory;
import java.util.ArrayList;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class WithdrawActivity extends MainActionBarActivity {
    private final String SPLIT_TEXT = "#1#";
    /* access modifiers changed from: private */
    public ReferenceAdapter<WithdrawReasonModel> mAdapter;
    private View mFooterView;
    private View mHeaderView;
    /* access modifiers changed from: private */
    public ListView mListView;
    /* access modifiers changed from: private */
    public WithdrawInfoModel mModel;
    private ArrayList<WithdrawReasonModel> mModels = new ArrayList<>();

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_withdraw, 2);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ud68c\uc6d0\ud0c8\ud1f4");
        GAEvent.onGAScreenView(this, R.string.ga_withdraw);
        this.mHeaderView = View.inflate(this, R.layout.header_withdraw, null);
        this.mFooterView = View.inflate(this, R.layout.footer_withdraw, null);
        this.mListView = (ListView) findViewById(R.id.listView);
        this.mListView.addHeaderView(this.mHeaderView);
        this.mListView.addFooterView(this.mFooterView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<WithdrawReasonModel>() {
            public View getView(WithdrawReasonModel model, int position) {
                return WithdrawViewFactory.createView(WithdrawActivity.this, model);
            }

            public void viewWillDisplay(View view, WithdrawReasonModel model) {
                view.findViewById(R.id.titleLabel).setSelected(model.isChecked());
            }
        });
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                int position2 = position - WithdrawActivity.this.mListView.getHeaderViewsCount();
                ((WithdrawReasonModel) WithdrawActivity.this.mAdapter.getItem(position2)).setChecked(!((WithdrawReasonModel) WithdrawActivity.this.mAdapter.getItem(position2)).isChecked());
                WithdrawActivity.this.mAdapter.notifyDataSetChanged();
            }
        });
        findViewById(R.id.emailEditButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) WithdrawActivity.this, (int) R.string.ga_withdraw, (int) R.string.ga_ev_click, (int) R.string.ga_withdraw_email);
                InputConfirmDialog dialog = new InputConfirmDialog(WithdrawActivity.this, "\uc774\uba54\uc77c\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", ((TextView) WithdrawActivity.this.findViewById(R.id.emailLabel)).getText().toString().trim());
                dialog.setOnOkClickListener(new onOkClickListener() {
                    public void onClick(InputConfirmDialog dialog, String email) {
                        ((TextView) WithdrawActivity.this.findViewById(R.id.emailLabel)).setText(email);
                    }
                });
                dialog.show();
            }
        });
        findViewById(R.id.confirmButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) WithdrawActivity.this, (int) R.string.ga_withdraw, (int) R.string.ga_ev_click, (int) R.string.ga_withdraw_complete);
                WithdrawActivity.this.getWithdrawParams();
            }
        });
        reqeustWithdrawInfoApi();
    }

    /* access modifiers changed from: private */
    public void settingUI() {
        ((TextView) this.mHeaderView.findViewById(R.id.descriptionLabel)).setText(this.mModel.getWithdraw_guide());
        ((TextView) findViewById(R.id.emailLabel)).setText(this.mModel.getUser_email());
        setWithdrawModel();
    }

    private void setWithdrawModel() {
        for (int i = 0; i < this.mModel.getReason_list().size(); i++) {
            WithdrawReasonModel model = new WithdrawReasonModel();
            model.setName(this.mModel.getReason_list().get(i));
            this.mModels.add(model);
        }
        this.mAdapter.addAll(this.mModels);
        this.mAdapter.notifyDataSetChanged();
    }

    /* access modifiers changed from: private */
    public void showDuplicateView() {
        findViewById(R.id.duplicateView).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
        findViewById(R.id.duplicateView).setVisibility(0);
        findViewById(R.id.confirmButton).setEnabled(false);
    }

    /* access modifiers changed from: private */
    public void getWithdrawParams() {
        String inputText = ((EditText) this.mFooterView.findViewById(R.id.inputField)).getText().toString().trim();
        String params = "";
        boolean isChecked = false;
        for (int i = 0; i < this.mAdapter.getCount(); i++) {
            if (((WithdrawReasonModel) this.mAdapter.getItem(i)).isChecked()) {
                params = params + ((WithdrawReasonModel) this.mAdapter.getItem(i)).getName() + "#1#";
                isChecked = true;
            }
        }
        if (isChecked || !inputText.isEmpty()) {
            final String finalParams = params + inputText;
            showConfirmDialog("\ud68c\uc6d0 \ud0c8\ud1f4\ub97c \uc2e0\uccad \ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c? \ucc98\ub9ac \uacfc\uc815\uc740 \n3~7\uc77c \uc815\ub3c4 \uc18c\uc694 \ub429\ub2c8\ub2e4.", new Runnable() {
                public void run() {
                    WithdrawActivity.this.requestWithdrawApi(finalParams);
                }
            });
            return;
        }
        showDialog("\ud558\ub098 \uc774\uc0c1\uc758 \ud56d\ubaa9\uc744 \uc120\ud0dd\ud574 \uc8fc\uc138\uc694!");
    }

    /* access modifiers changed from: private */
    public void reqeustWithdrawInfoApi() {
        new WithdrawInfoApi(this).request(new RequestHandler() {
            public void onStart() {
                WithdrawActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                new Handler().postDelayed(new Runnable() {
                    public void run() {
                        WithdrawActivity.this.showCircleDialog(false);
                    }
                }, 1000);
                WithdrawResultModel model = (WithdrawResultModel) result;
                if (model.getResult().equals("Y")) {
                    WithdrawActivity.this.mModel = model.getDetail_info();
                    WithdrawActivity.this.settingUI();
                } else if (model.getResult().equals("D")) {
                    WithdrawActivity.this.showDuplicateView();
                }
            }

            public void onFailure(Exception exception) {
                WithdrawActivity.this.showCircleDialog(false);
                WithdrawActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        WithdrawActivity.this.reqeustWithdrawInfoApi();
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestWithdrawApi(final String params) {
        WithdrawApi request = new WithdrawApi(this);
        request.addParam("user_email", ((TextView) findViewById(R.id.emailLabel)).getText().toString().trim());
        request.addParam("reason", params);
        request.request(new RequestHandler() {
            public void onStart() {
                WithdrawActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                WithdrawActivity.this.showCircleDialog(false);
                if (((BaseResultModel) result).getResult().equals("Y")) {
                    Toast.makeText(WithdrawActivity.this, "\ud68c\uc6d0\ud0c8\ud1f4\uc2e0\uccad\uc774 \uc644\ub8cc\ub418\uc5c8\uc2b5\ub2c8\ub2e4.", 0).show();
                    WithdrawActivity.this.finish();
                    return;
                }
                Toast.makeText(WithdrawActivity.this, "\ud68c\uc6d0\ud0c8\ud1f4\uc2e0\uccad\uc774 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4.\n\uc7a0\uc2dc\ud6c4 \ub2e4\uc2dc \uc2dc\ub3c4\ud574\uc8fc\uc138\uc694.", 0).show();
            }

            public void onFailure(Exception exception) {
                WithdrawActivity.this.showCircleDialog(false);
                WithdrawActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        WithdrawActivity.this.requestWithdrawApi(params);
                    }
                });
            }
        });
    }
}