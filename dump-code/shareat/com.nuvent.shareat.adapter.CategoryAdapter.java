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
import com.nuvent.shareat.model.store.CategoryModel;
import java.util.ArrayList;

public class CategoryAdapter extends BaseExpandableListAdapter {
    private Context mContext;
    private LayoutInflater mLayoutInflater;
    /* access modifiers changed from: private */
    public OnClickCell mListener;
    private ArrayList<CategoryModel> mModels;

    public interface OnClickCell {
        void onCheckItem(int i, int i2, boolean z);
    }

    class ViewHolder {
        public TextView mChildLeftCheckView;
        public TextView mChildRightCheckView;
        public ImageView mGroupArrow;
        public TextView mGroupTitle;

        ViewHolder() {
        }
    }

    public CategoryAdapter(Context context, ArrayList<CategoryModel> models) {
        this.mContext = context;
        this.mModels = models;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getGroupCount() {
        return this.mModels.size();
    }

    public int getChildrenCount(int groupPosition) {
        return (this.mModels.get(groupPosition).getChildModels().size() / 2) + (this.mModels.get(groupPosition).getChildModels().size() % 2 > 0 ? 1 : 0);
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
            convertView = this.mLayoutInflater.inflate(R.layout.cell_category_group, null);
            viewHolder.mGroupTitle = (TextView) convertView.findViewById(R.id.titleLabel);
            viewHolder.mGroupArrow = (ImageView) convertView.findViewById(R.id.arrowView);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        viewHolder.mGroupTitle.setText(this.mModels.get(groupPosition).getCategoryName());
        if (isExpanded) {
            viewHolder.mGroupArrow.setSelected(true);
        } else {
            viewHolder.mGroupArrow.setSelected(false);
        }
        return convertView;
    }

    public View getChildView(final int groupPosition, int childPosition, boolean isLastChild, View convertView, ViewGroup parent) {
        ViewHolder viewHolder = new ViewHolder();
        if (convertView == null) {
            convertView = this.mLayoutInflater.inflate(R.layout.cell_category_child, null);
            viewHolder.mChildLeftCheckView = (TextView) convertView.findViewById(R.id.leftCheckView);
            viewHolder.mChildRightCheckView = (TextView) convertView.findViewById(R.id.rightCheckView);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        final int leftPosition = childPosition * 2;
        final int rightPosition = leftPosition + 1;
        viewHolder.mChildLeftCheckView.setText(((CategoryModel) getChild(groupPosition, leftPosition)).getCategoryName());
        viewHolder.mChildLeftCheckView.setSelected(((CategoryModel) getChild(groupPosition, leftPosition)).isSelected().booleanValue());
        viewHolder.mChildLeftCheckView.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                v.setSelected(!v.isSelected());
                CategoryAdapter.this.mListener.onCheckItem(groupPosition, leftPosition, v.isSelected());
            }
        });
        try {
            viewHolder.mChildRightCheckView.setText(((CategoryModel) getChild(groupPosition, rightPosition)).getCategoryName());
            viewHolder.mChildRightCheckView.setSelected(((CategoryModel) getChild(groupPosition, rightPosition)).isSelected().booleanValue());
            viewHolder.mChildRightCheckView.setVisibility(0);
            viewHolder.mChildRightCheckView.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    v.setSelected(!v.isSelected());
                    CategoryAdapter.this.mListener.onCheckItem(groupPosition, rightPosition, v.isSelected());
                }
            });
        } catch (IndexOutOfBoundsException e) {
            viewHolder.mChildRightCheckView.setText("");
            viewHolder.mChildRightCheckView.setVisibility(8);
            viewHolder.mChildRightCheckView.setOnClickListener(null);
        }
        return convertView;
    }

    public void setOnClickCellListener(OnClickCell listener) {
        this.mListener = listener;
    }
}