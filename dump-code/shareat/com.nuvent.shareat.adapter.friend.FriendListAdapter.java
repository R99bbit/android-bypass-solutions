package com.nuvent.shareat.adapter.friend;

import android.content.Context;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.FriendStatusApi;
import com.nuvent.shareat.event.FriendStatusEvent;
import com.nuvent.shareat.model.friend.FriendModel;
import com.nuvent.shareat.model.friend.FriendResultModel;
import com.nuvent.shareat.model.friend.FriendStatusModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.TreeSet;
import net.xenix.util.ImageDisplay;

public class FriendListAdapter extends BaseAdapter {
    public static final int CELL_TYPE_FOLLOW = 2;
    public static final int CELL_TYPE_FOLLOWING = 3;
    public static final int CELL_TYPE_FRIEND = 1;
    private static final int TYPE_ITEM = 0;
    private static final int TYPE_MAX_COUNT = 2;
    private static final int TYPE_SEPARATOR = 1;
    private boolean isMine = true;
    /* access modifiers changed from: private */
    public int mCellType;
    /* access modifiers changed from: private */
    public Context mContext;
    /* access modifiers changed from: private */
    public ArrayList<FriendModel> mFriendModels;
    /* access modifiers changed from: private */
    public FriendResultModel mFriendResultModel;
    private LayoutInflater mLayoutInflater;
    private TreeSet<Integer> mSeparatorsSet = new TreeSet<>();

    class ViewHolder {
        ImageButton cancelButton;
        ImageButton confirmButton;
        LinearLayout confirmLayout;
        TextView countLabel;
        ImageButton followButton;
        ImageButton inviteButton;
        TextView nameLabel;
        ImageView profileImageView;
        TextView titleLabel;

        ViewHolder() {
        }
    }

    public FriendListAdapter(Context context) {
        this.mContext = context;
        this.mFriendResultModel = new FriendResultModel();
        this.mFriendModels = new ArrayList<>();
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public void setMine(boolean isMine2) {
        this.isMine = isMine2;
    }

    public int getCount() {
        return this.mFriendModels.size();
    }

    public Object getItem(int position) {
        return this.mFriendModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder = new ViewHolder();
        int type = getItemViewType(position);
        if (convertView == null) {
            switch (type) {
                case 0:
                    convertView = this.mLayoutInflater.inflate(R.layout.cell_friend, null);
                    viewHolder.nameLabel = (TextView) convertView.findViewById(R.id.nameLabel);
                    viewHolder.profileImageView = (ImageView) convertView.findViewById(R.id.profileImageView);
                    viewHolder.followButton = (ImageButton) convertView.findViewById(R.id.followButton);
                    viewHolder.confirmButton = (ImageButton) convertView.findViewById(R.id.confirmButton);
                    viewHolder.cancelButton = (ImageButton) convertView.findViewById(R.id.cancelButton);
                    viewHolder.confirmLayout = (LinearLayout) convertView.findViewById(R.id.confirmLayout);
                    viewHolder.inviteButton = (ImageButton) convertView.findViewById(R.id.inviteButton);
                    break;
                case 1:
                    convertView = this.mLayoutInflater.inflate(R.layout.cell_friend_header, null);
                    viewHolder.titleLabel = (TextView) convertView.findViewById(R.id.titleLabel);
                    viewHolder.countLabel = (TextView) convertView.findViewById(R.id.countLabel);
                    break;
            }
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        final FriendModel model = this.mFriendModels.get(position);
        switch (type) {
            case 0:
                viewHolder.followButton.setSelected(false);
                viewHolder.confirmLayout.setVisibility(8);
                viewHolder.followButton.setVisibility(8);
                viewHolder.inviteButton.setVisibility(8);
                ImageDisplay.getInstance().displayImageLoadListRound(model.getFriend_img(), viewHolder.profileImageView, this.mContext.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX));
                viewHolder.nameLabel.setText(model.getFriend_name());
                viewHolder.inviteButton.setVisibility(8);
                OnClickListener userProfileClickListener = new OnClickListener() {
                    public void onClick(View v) {
                        Intent intent = new Intent(FriendListAdapter.this.mContext, InterestActivity.class);
                        intent.putExtra("targetUserSno", model.getFriend_sno());
                        intent.putExtra("inMenu", "");
                        ((BaseActivity) FriendListAdapter.this.mContext).pushActivity(intent);
                    }
                };
                viewHolder.profileImageView.setOnClickListener(userProfileClickListener);
                viewHolder.nameLabel.setOnClickListener(userProfileClickListener);
                String followStatus = model.getFollow_status();
                if (followStatus.equals("00")) {
                    viewHolder.followButton.setVisibility(0);
                } else if (followStatus.equals("05")) {
                    viewHolder.confirmLayout.setVisibility(0);
                } else if (!followStatus.equals("07")) {
                    if (followStatus.equals("10")) {
                        viewHolder.followButton.setVisibility(0);
                        viewHolder.followButton.setSelected(true);
                    } else if (followStatus.equals("20")) {
                        viewHolder.followButton.setVisibility(0);
                        viewHolder.followButton.setSelected(true);
                    } else if (!followStatus.equals("50") && followStatus.equals("I")) {
                        viewHolder.followButton.setVisibility(0);
                        viewHolder.followButton.setSelected(false);
                    }
                }
                if (!this.isMine) {
                    viewHolder.confirmButton.setEnabled(false);
                    viewHolder.cancelButton.setEnabled(false);
                    break;
                } else {
                    viewHolder.followButton.setOnClickListener(new OnClickListener() {
                        public void onClick(final View v) {
                            String message;
                            if (v.isSelected()) {
                                GAEvent.onGaEvent(FriendListAdapter.this.mContext.getResources().getString(R.string.friend_group), FriendListAdapter.this.mContext.getResources().getString(R.string.ga_friends_unfollow), FriendListAdapter.this.mContext.getResources().getString(R.string.ga_friends_unfollow));
                                if (model.getFollow_status().equals("20")) {
                                    message = model.getFriend_name() + "\ub2d8\uc5d0 \ub300\ud55c \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?\n(\ub9de\ud314 \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uba74, \uce5c\uad6c\uc18c\uc2dd/\uacb0\uc81c\ucd08\ub300\ub97c \ubc1b\uc744 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4)";
                                } else {
                                    message = model.getFriend_name() + "\ub2d8\uc5d0 \ub300\ud55c \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?";
                                }
                                ((BaseActivity) FriendListAdapter.this.mContext).showConfirmDialog(message, new Runnable() {
                                    public void run() {
                                        v.setSelected(!v.isSelected());
                                        FriendListAdapter.this.requestStateApi(model);
                                    }
                                });
                                return;
                            }
                            GAEvent.onGaEvent(FriendListAdapter.this.mContext.getResources().getString(R.string.friend_group), FriendListAdapter.this.mContext.getResources().getString(R.string.ga_friends_follow), FriendListAdapter.this.mContext.getResources().getString(R.string.ga_friends_follow));
                            v.setSelected(!v.isSelected());
                            FriendListAdapter.this.requestStateApi(model);
                        }
                    });
                    viewHolder.confirmButton.setOnClickListener(new OnClickListener() {
                        public void onClick(View v) {
                            v.setSelected(!v.isSelected());
                            FriendListAdapter.this.requestStateApi("05", model);
                        }
                    });
                    viewHolder.cancelButton.setOnClickListener(new OnClickListener() {
                        public void onClick(View v) {
                            v.setSelected(!v.isSelected());
                            FriendListAdapter.this.requestStateApi("00", model);
                        }
                    });
                    break;
                }
            case 1:
                if (this.mCellType == 1) {
                    viewHolder.titleLabel.setText("\uce5c\uad6c(\ub9de\ud314)\ubaa9\ub85d");
                } else if (this.mCellType == 2) {
                    viewHolder.titleLabel.setText("\ud314\ub85c\uc6cc \ubaa9\ub85d");
                } else {
                    viewHolder.titleLabel.setText("\ud314\ub85c\uc789 \ubaa9\ub85d");
                }
                if (this.mFriendResultModel.getTotal_cnt() <= 0) {
                    viewHolder.titleLabel.setText("");
                    viewHolder.countLabel.setText("");
                    break;
                } else {
                    viewHolder.countLabel.setText("(" + this.mFriendResultModel.getTotal_cnt() + ")");
                    break;
                }
        }
        return convertView;
    }

    public void addSeparatorItem(int totalCount) {
        FriendModel model = new FriendModel();
        model.setTotalCount(totalCount);
        this.mFriendModels.add(model);
        this.mSeparatorsSet.add(Integer.valueOf(this.mFriendModels.size() - 1));
    }

    /* access modifiers changed from: private */
    public void requestStateApi(String statusCode, final FriendModel friendModel) {
        FriendStatusApi request = new FriendStatusApi(this.mContext);
        request.addParam("follow_user_sno", friendModel.getFriend_sno());
        if (statusCode == null) {
            statusCode = friendModel.getFollow_status();
        }
        request.addParam("follow_status", statusCode);
        request.request(new RequestHandler() {
            public void onStart() {
                ((BaseActivity) FriendListAdapter.this.mContext).showCircleDialog(true);
            }

            public void onResult(Object result) {
                FriendStatusModel model = (FriendStatusModel) result;
                if (model.getResult().equals("Y")) {
                    String status = model.getFollow_status();
                    if (FriendListAdapter.this.mCellType == 1) {
                        friendModel.setFollow_status(status);
                        if (!status.equals("20")) {
                            FriendListAdapter.this.mFriendModels.remove(friendModel);
                            FriendListAdapter.this.mFriendResultModel.setTotal_cnt(FriendListAdapter.this.mFriendResultModel.getTotal_cnt() - 1);
                        }
                        FriendListAdapter.this.notifyDataSetChanged();
                    } else if (FriendListAdapter.this.mCellType == 2) {
                        friendModel.setFollow_status(status);
                        FriendListAdapter.this.notifyDataSetChanged();
                    } else {
                        if (!status.equals("10")) {
                            FriendListAdapter.this.mFriendModels.remove(friendModel);
                            FriendListAdapter.this.mFriendResultModel.setTotal_cnt(FriendListAdapter.this.mFriendResultModel.getTotal_cnt() - 1);
                        }
                        friendModel.setFollow_status(status);
                        FriendListAdapter.this.notifyDataSetChanged();
                    }
                    EventBus.getDefault().post(new FriendStatusEvent(FriendListAdapter.this.mCellType, friendModel));
                }
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) FriendListAdapter.this.mContext).showCircleDialog(false);
            }

            public void onFinish() {
                ((BaseActivity) FriendListAdapter.this.mContext).showCircleDialog(false);
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestStateApi(FriendModel friendModel) {
        requestStateApi(null, friendModel);
    }

    public int getItemViewType(int position) {
        return this.mSeparatorsSet.contains(Integer.valueOf(position)) ? 1 : 0;
    }

    public int getViewTypeCount() {
        return 2;
    }

    public void setData(ArrayList<FriendModel> models) {
        this.mFriendModels.addAll(models);
    }

    public void setCellType(int type) {
        this.mCellType = type;
    }

    public void setData(FriendModel model) {
        this.mFriendModels.add(model);
    }

    public void dataClear() {
        this.mFriendModels.clear();
        notifyDataSetChanged();
    }

    public void setCellCount(FriendResultModel model) {
        this.mFriendResultModel = model;
    }
}