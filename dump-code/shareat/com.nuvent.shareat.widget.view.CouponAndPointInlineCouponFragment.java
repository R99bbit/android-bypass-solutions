package com.nuvent.shareat.widget.view;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ListView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.common.CouponAndPointActivity;
import com.nuvent.shareat.adapter.CouponAdapter;
import com.nuvent.shareat.api.CouponListApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.event.CircleDialogEvent;
import com.nuvent.shareat.event.CouponListEvent;
import com.nuvent.shareat.model.CouponDetailModel;
import com.nuvent.shareat.model.CouponModel;
import de.greenrobot.event.EventBus;
import java.util.Iterator;

public class CouponAndPointInlineCouponFragment extends Fragment implements OnClickListener {
    /* access modifiers changed from: private */
    public static View sView;
    /* access modifiers changed from: private */
    public CouponAdapter mCouponAdapter;
    /* access modifiers changed from: private */
    public CouponHeaderView mHeaderView;

    public void onEventMainThread(CircleDialogEvent event) {
        if (event != null) {
            ((CouponAndPointActivity) getActivity()).showCircleDialog(event.isShow());
        }
    }

    public void onEventMainThread(CouponListEvent event) {
        if (event != null) {
            requestCouponListApi();
        }
    }

    public void onClick(View v) {
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        EventBus.getDefault().register(this);
        ((CouponAndPointActivity) getActivity()).showFavoriteButton(false);
        sView = inflater.inflate(R.layout.activity_coupon_and_point_inline_coupon_view, container, false);
        this.mCouponAdapter = new CouponAdapter(getContext());
        this.mHeaderView = new CouponHeaderView(getContext());
        ListView listView = (ListView) sView.findViewById(R.id.usersCouponList);
        listView.addHeaderView(this.mHeaderView);
        listView.setAdapter(this.mCouponAdapter);
        requestCouponListApi();
        return sView;
    }

    /* access modifiers changed from: private */
    public void requestCouponListApi() {
        CouponListApi request = new CouponListApi(getContext());
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
                    CouponAndPointInlineCouponFragment.this.mCouponAdapter.setData(model.getResult_list());
                }
                int useableCount = 0;
                Iterator<CouponDetailModel> it = model.getResult_list().iterator();
                while (it.hasNext()) {
                    if (it.next().getCoupon_status().equals("00")) {
                        useableCount++;
                    }
                }
                CouponAndPointInlineCouponFragment.this.mHeaderView.setUseableCoupon(useableCount);
                if (model.getResult_list().size() == 0) {
                    CouponAndPointInlineCouponFragment.sView.findViewById(R.id.emptyCouponList).setVisibility(0);
                } else {
                    CouponAndPointInlineCouponFragment.sView.findViewById(R.id.emptyCouponList).setVisibility(8);
                }
            }

            public void onFailure(Exception exception) {
                ((CouponAndPointActivity) CouponAndPointInlineCouponFragment.this.getActivity()).handleException(exception, new Runnable() {
                    public void run() {
                        CouponAndPointInlineCouponFragment.this.requestCouponListApi();
                    }
                });
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }
}