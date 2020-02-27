package com.nuvent.shareat.activity.menu;

import android.os.Bundle;
import android.widget.ListView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.adapter.CouponAdapter;
import com.nuvent.shareat.api.CouponListApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.event.CircleDialogEvent;
import com.nuvent.shareat.event.CouponListEvent;
import com.nuvent.shareat.model.CouponDetailModel;
import com.nuvent.shareat.model.CouponModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CouponHeaderView;
import de.greenrobot.event.EventBus;
import java.util.Iterator;

public class CouponActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public CouponAdapter mCouponAdapter;
    /* access modifiers changed from: private */
    public CouponHeaderView mHeaderView;

    public void onEventMainThread(CircleDialogEvent event) {
        if (event != null) {
            showCircleDialog(event.isShow());
        }
    }

    public void onEventMainThread(CouponListEvent event) {
        if (event != null) {
            requestCouponListApi();
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_coupon, 2);
        GAEvent.onGAScreenView(this, R.string.ga_my_coupon);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\ub0b4 \ucfe0\ud3f0\uad00\ub9ac");
        this.mCouponAdapter = new CouponAdapter(this);
        this.mHeaderView = new CouponHeaderView(this);
        ListView listView = (ListView) findViewById(R.id.listView);
        listView.addHeaderView(this.mHeaderView);
        listView.setAdapter(this.mCouponAdapter);
        requestCouponListApi();
    }

    /* access modifiers changed from: private */
    public void requestCouponListApi() {
        CouponListApi request = new CouponListApi(this);
        request.addParam("list_gubun", "A");
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                CouponModel model = (CouponModel) result;
                if (model.getResult().equals("Y")) {
                    CouponActivity.this.mCouponAdapter.setData(model.getResult_list());
                }
                int useableCount = 0;
                Iterator<CouponDetailModel> it = model.getResult_list().iterator();
                while (it.hasNext()) {
                    if (it.next().getCoupon_status().equals("00")) {
                        useableCount++;
                    }
                }
                CouponActivity.this.mHeaderView.setUseableCoupon(useableCount);
                TextView emptyLabel = (TextView) CouponActivity.this.findViewById(R.id.emptyLabel);
                ListView listView = (ListView) CouponActivity.this.findViewById(R.id.listView);
                if (model.getResult_list().size() == 0) {
                    emptyLabel.setVisibility(0);
                } else {
                    emptyLabel.setVisibility(8);
                }
            }

            public void onFailure(Exception exception) {
                CouponActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        CouponActivity.this.requestCouponListApi();
                    }
                });
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }
}