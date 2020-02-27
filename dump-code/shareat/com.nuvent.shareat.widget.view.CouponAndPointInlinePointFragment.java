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
import com.nuvent.shareat.adapter.PointAdapter;
import com.nuvent.shareat.api.PointListApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.model.PointModel;

public class CouponAndPointInlinePointFragment extends Fragment implements OnClickListener {
    /* access modifiers changed from: private */
    public static View sView;
    /* access modifiers changed from: private */
    public PointHeaderView mHeaderView;
    /* access modifiers changed from: private */
    public PointAdapter mPointAdapter;

    public void onClick(View v) {
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        ((CouponAndPointActivity) getActivity()).showFavoriteButton(false);
        sView = inflater.inflate(R.layout.activity_coupon_and_point_inline_point_view, container, false);
        this.mPointAdapter = new PointAdapter(getContext());
        this.mHeaderView = new PointHeaderView(getContext());
        ListView listView = (ListView) sView.findViewById(R.id.usersPointList);
        listView.addHeaderView(this.mHeaderView);
        listView.setAdapter(this.mPointAdapter);
        requestPointListApi();
        return sView;
    }

    /* access modifiers changed from: private */
    public void requestPointListApi() {
        PointListApi request = new PointListApi(getContext());
        request.addParam("list_gubun", "A");
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                PointModel model = (PointModel) result;
                if (model.getResult().equals("Y")) {
                    CouponAndPointInlinePointFragment.this.mPointAdapter.setData(model.getResult_list());
                }
                CouponAndPointInlinePointFragment.this.mHeaderView.setPointTotalRemained(model.getResult_point());
                CouponAndPointInlinePointFragment.this.mHeaderView.setPointToBeExpired(model.getResult_expire_point());
                if (model.getResult_list().size() == 0) {
                    CouponAndPointInlinePointFragment.sView.findViewById(R.id.emptyPointList).setVisibility(0);
                } else {
                    CouponAndPointInlinePointFragment.sView.findViewById(R.id.emptyPointList).setVisibility(8);
                }
            }

            public void onFailure(Exception exception) {
                ((CouponAndPointActivity) CouponAndPointInlinePointFragment.this.getActivity()).handleException(exception, new Runnable() {
                    public void run() {
                        CouponAndPointInlinePointFragment.this.requestPointListApi();
                    }
                });
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }
}