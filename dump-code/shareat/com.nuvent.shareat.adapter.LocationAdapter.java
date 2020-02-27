package com.nuvent.shareat.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseExpandableListAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.LocationModel;
import java.util.ArrayList;

public class LocationAdapter extends BaseExpandableListAdapter {
    private Context mContext;
    private LayoutInflater mLayoutInflater;
    /* access modifiers changed from: private */
    public OnClickCell mListener;
    private ArrayList<LocationModel> mModels;

    public interface OnClickCell {
        void onClickCell(int i, int i2);
    }

    class ViewHolder {
        public TextView mChildCount;
        public TextView mChildTitle;
        public ImageView mGroupArrow;
        public TextView mGroupCount;
        public TextView mGroupTitle;

        ViewHolder() {
        }
    }

    public LocationAdapter(Context context, ArrayList<LocationModel> models) {
        this.mContext = context;
        this.mModels = models;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getGroupCount() {
        return this.mModels.size();
    }

    public int getChildrenCount(int groupPosition) {
        return this.mModels.get(groupPosition).getChildModels().size();
    }

    public Object getGroup(int groupPosition) {
        return this.mModels.get(groupPosition);
    }

    public Object getChild(int groupPosition, int childPosition) {
        return this.mModels.get(groupPosition).getChildModels().get(childPosition);
    }

    public long getGroupId(int groupPosition) {
        return 0;
    }

    public long getChildId(int groupPosition, int childPosition) {
        return 0;
    }

    public boolean hasStableIds() {
        return true;
    }

    public boolean isChildSelectable(int groupPosition, int childPosition) {
        return true;
    }

    public View getGroupView(int groupPosition, boolean isExpanded, View convertView, ViewGroup parent) {
        ViewHolder viewHolder = new ViewHolder();
        if (convertView == null) {
            convertView = this.mLayoutInflater.inflate(R.layout.cell_location_group, null);
            viewHolder.mGroupTitle = (TextView) convertView.findViewById(R.id.titleLabel);
            viewHolder.mGroupArrow = (ImageView) convertView.findViewById(R.id.arrowView);
            viewHolder.mGroupCount = (TextView) convertView.findViewById(R.id.countLabel);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        viewHolder.mGroupTitle.setText(this.mModels.get(groupPosition).getAreaName());
        viewHolder.mGroupCount.setText(this.mModels.get(groupPosition).getCntArea());
        if (isExpanded) {
            viewHolder.mGroupArrow.setSelected(true);
        } else {
            viewHolder.mGroupArrow.setSelected(false);
        }
        return convertView;
    }

    public View getChildView(final int groupPosition, final int childPosition, boolean isLastChild, View convertView, ViewGroup parent) {
        ViewHolder viewHolder = new ViewHolder();
        if (convertView == null) {
            convertView = this.mLayoutInflater.inflate(R.layout.cell_location_child, null);
            viewHolder.mChildTitle = (TextView) convertView.findViewById(R.id.childTitleLabel);
            viewHolder.mChildCount = (TextView) convertView.findViewById(R.id.childCountLabel);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        viewHolder.mChildTitle.setText(((LocationModel) getChild(groupPosition, childPosition)).getAreaName());
        viewHolder.mChildCount.setText(((LocationModel) getChild(groupPosition, childPosition)).getCntArea());
        convertView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                LocationAdapter.this.mListener.onClickCell(groupPosition, childPosition);
            }
        });
        return convertView;
    }

    public void setOnClickCellListener(OnClickCell listener) {
        this.mListener = listener;
    }
}