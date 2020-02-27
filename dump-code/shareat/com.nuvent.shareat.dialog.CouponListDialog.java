package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.CouponDetailModel;
import com.nuvent.shareat.widget.factory.CouponViewFactory;
import java.util.ArrayList;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class CouponListDialog extends BaseDialog implements OnClickListener {
    /* access modifiers changed from: private */
    public ReferenceAdapter<CouponDetailModel> mAdapter;
    private ListView mListView;
    private GetCoupon mListener;
    private ArrayList<CouponDetailModel> mModels;
    private View mRootView;

    public interface GetCoupon {
        void onNotUsed();

        void onSelectCoupon(CouponDetailModel couponDetailModel);
    }

    public CouponListDialog(Context context, ArrayList<CouponDetailModel> models) {
        super(context);
        this.mModels = models;
        setUnCheck();
        init();
        setCanceledOnTouchOutside(true);
        setCheck(0);
    }

    private void init() {
        this.mRootView = View.inflate(getContext(), R.layout.dialog_coupon_list, null);
        setContentView(this.mRootView);
        this.mListView = (ListView) this.mRootView.findViewById(R.id.listView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<CouponDetailModel>() {
            public View getView(CouponDetailModel model, int position) {
                return CouponViewFactory.createView(CouponListDialog.this.getContext(), model);
            }

            public void viewWillDisplay(View convertView, CouponDetailModel model) {
                ((ImageView) convertView.findViewById(R.id.checkButton)).setImageResource(model.isChecked() ? R.drawable.abc_btn_radio_to_on_mtrl_015 : R.drawable.abc_btn_radio_to_on_mtrl_000);
            }
        });
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                CouponListDialog.this.setCheck(position);
                CouponListDialog.this.mAdapter.notifyDataSetChanged();
            }
        });
        this.mAdapter.addAll(this.mModels);
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        this.mRootView.findViewById(R.id.cancelButton).setOnClickListener(this);
        this.mRootView.findViewById(R.id.doneButton).setOnClickListener(this);
    }

    private void setUnCheck() {
        for (int i = 0; i < this.mModels.size(); i++) {
            this.mModels.get(i).setChecked(false);
        }
    }

    /* access modifiers changed from: private */
    public void setCheck(int position) {
        for (int i = 0; i < this.mModels.size(); i++) {
            if (i == position) {
                this.mModels.get(i).setChecked(true);
            } else {
                this.mModels.get(i).setChecked(false);
            }
        }
    }

    private CouponDetailModel getSelectedCoupon() {
        CouponDetailModel model = null;
        for (int i = 0; i < this.mModels.size(); i++) {
            if (this.mModels.get(i).isChecked()) {
                model = this.mModels.get(i);
            }
        }
        return model;
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.cancelButton /*2131296415*/:
                this.mListener.onNotUsed();
                dismiss();
                return;
            case R.id.doneButton /*2131296617*/:
                CouponDetailModel model = getSelectedCoupon();
                if (model == null) {
                    Toast.makeText(getContext(), "\uc801\uc6a9\ud560 \ucfe0\ud3f0\uc744 \uc120\ud0dd\ud574\uc8fc\uc138\uc694.", 0).show();
                    return;
                }
                this.mListener.onSelectCoupon(model);
                dismiss();
                return;
            default:
                return;
        }
    }

    public void setOnSelectedCoupon(GetCoupon listener) {
        this.mListener = listener;
    }
}