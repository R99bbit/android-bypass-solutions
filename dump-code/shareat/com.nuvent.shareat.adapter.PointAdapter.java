package com.nuvent.shareat.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.PointDetailModel;
import java.util.ArrayList;

public class PointAdapter extends BaseAdapter {
    private Context mContext;
    private LayoutInflater mLayoutInflater;
    private ArrayList<PointDetailModel> mPointModels = new ArrayList<>();

    class ViewHolder {
        TextView partnerName;
        LinearLayout pointAmountLayoutMinus;
        LinearLayout pointAmountLayoutPlus;
        TextView pointAmountMinus;
        TextView pointAmountPlus;
        LinearLayout pointCellLayout;
        TextView pointDesc;
        TextView pointType;
        TextView savingDate;

        ViewHolder() {
        }
    }

    public PointAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return this.mPointModels.size();
    }

    public Object getItem(int position) {
        return this.mPointModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = this.mLayoutInflater.inflate(R.layout.cell_point, null);
            viewHolder.pointCellLayout = (LinearLayout) convertView.findViewById(R.id.pointCellLayout);
            viewHolder.pointAmountLayoutPlus = (LinearLayout) convertView.findViewById(R.id.pointAmountLayoutPlus);
            viewHolder.pointAmountLayoutMinus = (LinearLayout) convertView.findViewById(R.id.pointAmountLayoutMinus);
            viewHolder.partnerName = (TextView) convertView.findViewById(R.id.pointPartnerName);
            viewHolder.savingDate = (TextView) convertView.findViewById(R.id.pointSavingDate);
            viewHolder.pointType = (TextView) convertView.findViewById(R.id.pointType);
            viewHolder.pointAmountPlus = (TextView) convertView.findViewById(R.id.pointAmountPlus);
            viewHolder.pointAmountMinus = (TextView) convertView.findViewById(R.id.pointAmountMinus);
            viewHolder.pointDesc = (TextView) convertView.findViewById(R.id.pointDesc);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        PointDetailModel model = this.mPointModels.get(position);
        viewHolder.partnerName.setText(model.getUsed_partner_name());
        viewHolder.pointType.setText(model.getDeal_type());
        viewHolder.savingDate.setText(model.getUse_datetime_text());
        viewHolder.pointDesc.setText(model.getPoint_description());
        int pointAmount = Integer.parseInt(model.getI_use_amt());
        if (pointAmount > 0) {
            viewHolder.pointAmountLayoutPlus.setVisibility(0);
            viewHolder.pointAmountLayoutMinus.setVisibility(8);
            viewHolder.pointAmountPlus.setText(String.valueOf(pointAmount));
        } else {
            viewHolder.pointAmountLayoutMinus.setVisibility(0);
            viewHolder.pointAmountLayoutPlus.setVisibility(8);
            viewHolder.pointAmountMinus.setText(String.valueOf(Math.abs(pointAmount)));
        }
        return convertView;
    }

    public void setData(ArrayList<PointDetailModel> models) {
        this.mPointModels = models;
        notifyDataSetChanged();
    }
}