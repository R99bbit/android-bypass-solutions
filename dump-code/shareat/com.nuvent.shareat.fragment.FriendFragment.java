package com.nuvent.shareat.fragment;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.AbsListView.OnScrollListener;
import android.widget.ListView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.menu.FriendGroupActivity;
import com.nuvent.shareat.adapter.friend.FriendListAdapter;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.FriendApi;
import com.nuvent.shareat.event.FriendAddEvent;
import com.nuvent.shareat.event.FriendStatusEvent;
import com.nuvent.shareat.model.friend.FriendModel;
import com.nuvent.shareat.model.friend.FriendResultModel;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;

public class FriendFragment extends Fragment {
    public static final int FRINED_VIEW_TYPE_FOLLOW = 2;
    public static final int FRINED_VIEW_TYPE_FOLLOWING = 3;
    public static final int FRINED_VIEW_TYPE_FRIEND = 1;
    private static final int VIEW_COUNT = 20;
    /* access modifiers changed from: private */
    public boolean isComplete = false;
    /* access modifiers changed from: private */
    public boolean isLoading = false;
    /* access modifiers changed from: private */
    public FriendListAdapter mFriendListAdapter;
    /* access modifiers changed from: private */
    public ArrayList<FriendModel> mFriendModels;
    /* access modifiers changed from: private */
    public int mPageCount;
    private int mType;

    public void onEventMainThread(FriendAddEvent event) {
        if (((FriendGroupActivity) getActivity()).getTargetUserSno() == null) {
            if (this.mType == 1 || event.getTargetSno() == null || event.getTargetSno().isEmpty()) {
                this.mFriendListAdapter.dataClear();
                this.mFriendModels.clear();
                this.mPageCount = 1;
                requestFrinedListApi();
                return;
            }
            int i = 0;
            while (true) {
                if (i >= this.mFriendModels.size()) {
                    break;
                } else if (this.mFriendModels.get(i).getFriend_sno().equals(event.getTargetSno())) {
                    this.mFriendModels.get(i).setFollow_status(event.getFollowStatus());
                    break;
                } else {
                    i++;
                }
            }
            this.mFriendListAdapter.notifyDataSetChanged();
        }
    }

    public void onEventMainThread(FriendStatusEvent event) {
        if (((FriendGroupActivity) getActivity()).getTargetUserSno() == null && event != null && this.mType != event.getRequestType()) {
            this.isComplete = false;
            this.mPageCount = 1;
            this.mFriendListAdapter.dataClear();
            this.mFriendModels.clear();
            requestFrinedListApi();
        }
    }

    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
    }

    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    @Nullable
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_friend_list, container, false);
        this.mFriendListAdapter = new FriendListAdapter(getActivity());
        ListView listView = (ListView) view.findViewById(R.id.listView);
        listView.setBackgroundColor(-1);
        listView.setAdapter(this.mFriendListAdapter);
        this.mFriendModels = new ArrayList<>();
        this.mPageCount = 1;
        listView.setOnScrollListener(new OnScrollListener() {
            public void onScrollStateChanged(AbsListView view, int scrollState) {
            }

            public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
                if (FriendFragment.this.mFriendListAdapter != null && FriendFragment.this.mFriendListAdapter.getCount() > 0 && firstVisibleItem + visibleItemCount == totalItemCount && !FriendFragment.this.isLoading && !FriendFragment.this.isComplete) {
                    FriendFragment.this.isLoading = true;
                    FriendFragment.this.requestFrinedListApi();
                }
            }
        });
        requestFrinedListApi();
        return view;
    }

    /* access modifiers changed from: private */
    public void requestFrinedListApi() {
        FriendApi request = new FriendApi(getActivity());
        if (((FriendGroupActivity) getActivity()).getTargetUserSno() != null) {
            request.addParam("target_user", ((FriendGroupActivity) getActivity()).getTargetUserSno());
            this.mFriendListAdapter.setMine(false);
        }
        request.addParam("page", String.valueOf(this.mPageCount));
        request.addParam("view_cnt", String.valueOf(20));
        switch (this.mType) {
            case 1:
                request.addParam("follow_gubun", "F");
                this.mFriendListAdapter.setCellType(1);
                break;
            case 2:
                request.addParam("follow_gubun", "R");
                this.mFriendListAdapter.setCellType(2);
                break;
            case 3:
                request.addParam("follow_gubun", "S");
                this.mFriendListAdapter.setCellType(3);
                break;
        }
        if (this.mFriendModels.size() > 0) {
            request.addParam("last_index", this.mFriendModels.get(this.mFriendModels.size() - 1).getLast_index());
        } else {
            request.addParam("last_index", AppEventsConstants.EVENT_PARAM_VALUE_NO);
        }
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                FriendResultModel model = (FriendResultModel) result;
                if (model.getResult().equals("Y")) {
                    if (model.getResult_list().size() > 0) {
                        if (model.getResult_list().size() > 0 && FriendFragment.this.mPageCount == 1) {
                            FriendFragment.this.mFriendListAdapter.addSeparatorItem(model.getTotal_cnt());
                        }
                        for (int i = 0; i < model.getResult_list().size(); i++) {
                            FriendModel friendModel = model.getResult_list().get(i);
                            if (!friendModel.getFollow_status().equals("07")) {
                                if (i != 0 || FriendFragment.this.mFriendModels.size() <= 0) {
                                    if (model.getResult_list().size() > 1 && i > 0 && !model.getResult_list().get(i - 1).getFollow_status().equals("07") && !model.getResult_list().get(i - 1).getFollow_status().equals(friendModel.getFollow_status()) && (friendModel.getFollow_status().equals("05") || model.getResult_list().get(i - 1).getFollow_status().equals("05") || friendModel.getFollow_status().equals("I") || model.getResult_list().get(i - 1).getFollow_status().equals("I"))) {
                                        FriendFragment.this.mFriendListAdapter.addSeparatorItem(model.getTotal_cnt());
                                    }
                                } else if (!((FriendModel) FriendFragment.this.mFriendModels.get(FriendFragment.this.mFriendModels.size() - 1)).getFollow_status().equals(friendModel.getFollow_status()) && (friendModel.getFollow_status().equals("05") || ((FriendModel) FriendFragment.this.mFriendModels.get(FriendFragment.this.mFriendModels.size() - 1)).getFollow_status().equals("05") || friendModel.getFollow_status().equals("I") || ((FriendModel) FriendFragment.this.mFriendModels.get(FriendFragment.this.mFriendModels.size() - 1)).getFollow_status().equals("I"))) {
                                    FriendFragment.this.mFriendListAdapter.addSeparatorItem(model.getTotal_cnt());
                                }
                                FriendFragment.this.mFriendListAdapter.setData(friendModel);
                                FriendFragment.this.mFriendListAdapter.setCellCount(model);
                            }
                        }
                        FriendFragment.this.mFriendModels.addAll(model.getResult_list());
                        FriendFragment.this.mPageCount = FriendFragment.this.mPageCount + 1;
                        FriendFragment.this.isComplete = false;
                        FriendFragment.this.mFriendListAdapter.notifyDataSetChanged();
                        if (FriendFragment.this.mFriendModels.size() >= model.getTotal_cnt()) {
                            FriendFragment.this.isComplete = true;
                        }
                    } else {
                        FriendFragment.this.isComplete = true;
                    }
                    FriendFragment.this.isLoading = false;
                }
            }

            public void onFailure(Exception exception) {
                if (((BaseActivity) FriendFragment.this.getActivity()) != null) {
                    ((BaseActivity) FriendFragment.this.getActivity()).handleException(exception, new Runnable() {
                        public void run() {
                            FriendFragment.this.requestFrinedListApi();
                        }
                    });
                }
            }
        });
    }

    public void setType(int type) {
        this.mType = type;
    }
}