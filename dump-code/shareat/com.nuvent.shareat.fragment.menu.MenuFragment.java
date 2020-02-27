package com.nuvent.shareat.fragment.menu;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreMenuDetailApi;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.model.store.StoreMenuModel;
import com.nuvent.shareat.model.store.StoreMenuResultModel;
import com.nuvent.shareat.widget.factory.MenuViewFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class MenuFragment extends Fragment {
    /* access modifiers changed from: private */
    public ReferenceAdapter<StoreMenuModel> mAdapter;
    private TextView mDateLabel;
    private ListView mListView;
    /* access modifiers changed from: private */
    public String mMenuResultSet;
    private String mPartnerSno;
    private String mType;

    public void setMenuData(String sno, String type, String resultSet) {
        this.mPartnerSno = sno;
        this.mType = type;
        this.mMenuResultSet = resultSet;
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = View.inflate(getActivity(), R.layout.fragment_menu, null);
        this.mDateLabel = (TextView) view.findViewById(R.id.dateLabel);
        if (this.mMenuResultSet == null || !this.mMenuResultSet.equals("ES")) {
            this.mDateLabel.setVisibility(8);
        }
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<StoreMenuModel>() {
            public View getView(StoreMenuModel model, int position) {
                return MenuViewFactory.createView(MenuFragment.this.getActivity(), model, MenuFragment.this.mMenuResultSet);
            }

            public void viewWillDisplay(View view, StoreMenuModel model) {
            }
        });
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        requestMenuListApi();
        return view;
    }

    private void requestMenuListApi() {
        String parameter = String.format("?partner_sno=%s&result_set=%s&period=%s", new Object[]{this.mPartnerSno, this.mMenuResultSet, this.mType});
        StoreMenuDetailApi request = new StoreMenuDetailApi(getActivity());
        request.addGetParam(parameter);
        request.request(new RequestHandler() {
            public void onStart() {
                ((BaseActivity) MenuFragment.this.getActivity()).showCircleDialog(true);
            }

            public void onResult(Object result) {
                ((BaseActivity) MenuFragment.this.getActivity()).showCircleDialog(false);
                StoreMenuResultModel model = (StoreMenuResultModel) result;
                MenuFragment.this.mAdapter.addAll(model.getResult_list());
                MenuFragment.this.setResultDate(model.getResult_date());
                MenuFragment.this.mAdapter.notifyDataSetChanged();
            }

            public void onFailure(Exception exception) {
                if (MenuFragment.this.getActivity() != null) {
                    ((BaseActivity) MenuFragment.this.getActivity()).showCircleDialog(false);
                }
            }

            public void onFinish() {
                ((BaseActivity) MenuFragment.this.getActivity()).showCircleDialog(false);
            }
        });
    }

    /* access modifiers changed from: private */
    public void setResultDate(String dateString) {
        if (dateString == null || dateString.isEmpty()) {
            this.mDateLabel.setText("");
            return;
        }
        Date date = null;
        try {
            date = new SimpleDateFormat("yyyy-MM-dd").parse(dateString);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        this.mDateLabel.setText(new SimpleDateFormat(StoreInstaModel.MESSAGE_CARD_TIME_FORMAT).format(date) + " \uae30\uc900");
    }
}