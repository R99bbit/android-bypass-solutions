package com.nuvent.shareat.adapter.friend;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import com.igaworks.adbrix.IgawAdbrix;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.friend.FriendStatusApi;
import com.nuvent.shareat.event.FriendAddEvent;
import com.nuvent.shareat.model.friend.FriendModel;
import com.nuvent.shareat.model.friend.FriendResultModel;
import com.nuvent.shareat.model.friend.FriendStatusModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.ShareAtUtil;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import java.util.TreeSet;
import net.xenix.util.ImageDisplay;

public class AddressAdapter extends BaseAdapter {
    private static final int TYPE_ITEM = 0;
    private static final int TYPE_MAX_COUNT = 2;
    private static final int TYPE_SEPARATOR = 1;
    /* access modifiers changed from: private */
    public Context mContext;
    private ArrayList<FriendModel> mFriendModels = new ArrayList<>();
    private FriendResultModel mFriendResultModel = new FriendResultModel();
    private LayoutInflater mLayoutInflater;
    private TreeSet<Integer> mSeparatorsSet = new TreeSet<>();

    class ViewHolder {
        TextView countLabel;
        ImageButton followButton;
        ImageButton inviteButton;
        TextView nameLabel;
        ImageView profileImageView;
        TextView titleLabel;

        ViewHolder() {
        }
    }

    public AddressAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
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
                    convertView = this.mLayoutInflater.inflate(R.layout.cell_add_friend, null);
                    viewHolder.nameLabel = (TextView) convertView.findViewById(R.id.nameLabel);
                    viewHolder.profileImageView = (ImageView) convertView.findViewById(R.id.profileImageView);
                    viewHolder.followButton = (ImageButton) convertView.findViewById(R.id.followButton);
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
                ImageDisplay.getInstance().displayImageLoadListRound(model.getUser_img(), viewHolder.profileImageView, this.mContext.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX));
                if (model.getUser_name() == null || model.getUser_name().equals("")) {
                    viewHolder.nameLabel.setText(model.getName());
                } else {
                    viewHolder.nameLabel.setText(model.getUser_name());
                }
                viewHolder.inviteButton.setVisibility(8);
                viewHolder.followButton.setVisibility(8);
                viewHolder.followButton.setSelected(false);
                final String followStatus = model.getFollow_status();
                if (followStatus != null) {
                    if (followStatus.equals("I") || followStatus.equals("00") || followStatus.equals("05")) {
                        viewHolder.followButton.setVisibility(0);
                    } else if (followStatus.equals("10") || followStatus.equals("20")) {
                        viewHolder.followButton.setVisibility(0);
                        viewHolder.followButton.setSelected(true);
                    } else {
                        viewHolder.followButton.setVisibility(0);
                    }
                } else if (model.getUser_phone() != null) {
                    viewHolder.inviteButton.setVisibility(0);
                }
                viewHolder.profileImageView.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        if (followStatus != null) {
                            Intent intent = new Intent(AddressAdapter.this.mContext, InterestActivity.class);
                            intent.putExtra("targetUserSno", model.getUser_sno());
                            intent.putExtra("inMenu", "");
                            ((BaseActivity) AddressAdapter.this.mContext).pushActivity(intent);
                        }
                    }
                });
                viewHolder.followButton.setOnClickListener(new OnClickListener() {
                    public void onClick(final View v) {
                        String name;
                        String message;
                        if (v.isSelected()) {
                            GAEvent.onGaEvent(AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_add_friend), AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_unfollow), AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_unfollow));
                            if (model.getFollow_status().equals("20")) {
                                message = (model.getUser_name() != null ? model.getUser_name() : model.getName()) + "\ub2d8\uc5d0 \ub300\ud55c \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?\n(\ub9de\ud314 \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uba74, \uce5c\uad6c\uc18c\uc2dd/\uacb0\uc81c\ucd08\ub300\ub97c \ubc1b\uc744 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4)";
                            } else {
                                StringBuilder sb = new StringBuilder();
                                if (model.getUser_name() != null) {
                                    name = model.getUser_name();
                                } else {
                                    name = model.getName();
                                }
                                message = sb.append(name).append("\ub2d8\uc5d0 \ub300\ud55c \ud314\ub85c\uc6b0\ub97c \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?").toString();
                            }
                            ((BaseActivity) AddressAdapter.this.mContext).showConfirmDialog(message, new Runnable() {
                                public void run() {
                                    v.setSelected(!v.isSelected());
                                    AddressAdapter.this.requestStateApi(model);
                                }
                            });
                            return;
                        }
                        GAEvent.onGaEvent(AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_add_friend), AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_follow), AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_follow));
                        v.setSelected(!v.isSelected());
                        AddressAdapter.this.requestStateApi(model);
                    }
                });
                viewHolder.inviteButton.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent(AddressAdapter.this.mContext.getResources().getString(R.string.ga_friends_add_friend), AddressAdapter.this.mContext.getResources().getString(R.string.ga_ev_invite), AddressAdapter.this.mContext.getResources().getString(R.string.ga_add_friends_sms));
                        Uri smsUri = Uri.parse("sms:" + model.getUser_phone());
                        Intent retunIt = new Intent("android.intent.action.SENDTO");
                        retunIt.setData(smsUri);
                        retunIt.putExtra("sms_body", ShareAtUtil.getSharedUrl(1));
                        IgawAdbrix.retention("invite", "sms");
                        AddressAdapter.this.mContext.startActivity(retunIt);
                    }
                });
                break;
            case 1:
                if (this.mFriendModels.get(position + 1).getFollow_status() != null) {
                    viewHolder.titleLabel.setText("\uc0ac\uc6a9\uc911\uc778 \uc8fc\uc18c\ub85d \uce5c\uad6c ");
                    viewHolder.countLabel.setText("(" + model.getTotalCount() + ")");
                    break;
                } else {
                    viewHolder.titleLabel.setText("\uc8fc\uc18c\ub85d \uce5c\uad6c \ucd08\ub300\ud558\uae30 ");
                    viewHolder.countLabel.setText("(" + model.getTotalCount() + ")");
                    break;
                }
        }
        return convertView;
    }

    /* access modifiers changed from: private */
    public void requestStateApi(final FriendModel model) {
        FriendStatusApi request = new FriendStatusApi(this.mContext);
        request.addParam("follow_user_sno", model.getUser_sno());
        request.addParam("follow_status", model.getFollow_status());
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                FriendStatusModel resultModel = (FriendStatusModel) result;
                if (resultModel.getResult().equals("Y")) {
                    if (resultModel.getFollow_status() != null && !resultModel.getFollow_status().isEmpty()) {
                        model.setFollow_status(resultModel.getFollow_status());
                        AddressAdapter.this.notifyDataSetChanged();
                    }
                    EventBus.getDefault().post(new FriendAddEvent());
                }
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    public void setData(ArrayList<FriendModel> models) {
        this.mFriendModels.addAll(models);
    }

    public void setData(FriendModel model) {
        this.mFriendModels.add(model);
    }

    public void addSeparatorItem(int totalCount) {
        FriendModel model = new FriendModel();
        model.setTotalCount(totalCount);
        this.mFriendModels.add(model);
        if (this.mFriendModels.size() == 0) {
            this.mSeparatorsSet.add(Integer.valueOf(0));
        } else {
            this.mSeparatorsSet.add(Integer.valueOf(this.mFriendModels.size() - 1));
        }
    }

    public int getItemViewType(int position) {
        return this.mSeparatorsSet.contains(Integer.valueOf(position)) ? 1 : 0;
    }

    public int getViewTypeCount() {
        return 2;
    }

    public void dataClear() {
        this.mFriendModels.clear();
        notifyDataSetChanged();
    }

    public void setCellCount(FriendResultModel model) {
        this.mFriendResultModel = model;
    }

    public void addFirstSeparatorItem(int count) {
        this.mFriendModels.get(0).setTotalCount(count);
    }
}