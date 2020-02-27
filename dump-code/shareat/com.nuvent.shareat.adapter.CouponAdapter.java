package com.nuvent.shareat.adapter;

import android.content.Context;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.CouponDetailModel;
import java.util.ArrayList;
import net.xenix.util.FormatUtil;

public class CouponAdapter extends BaseAdapter {
    private Context mContext;
    private ArrayList<CouponDetailModel> mCouponModels = new ArrayList<>();
    private LayoutInflater mLayoutInflater;

    class ViewHolder {
        LinearLayout couponCellLayout;
        TextView dateLabel;
        TextView descriptionLabel;
        ImageView labelImageView;
        TextView titleCountLabel;
        TextView titleLabel;
        TextView titleTextLabel;
        TextView usePlaceLabel;

        ViewHolder() {
        }
    }

    public CouponAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return this.mCouponModels.size();
    }

    public Object getItem(int position) {
        return this.mCouponModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = this.mLayoutInflater.inflate(R.layout.cell_coupon, null);
            viewHolder.labelImageView = (ImageView) convertView.findViewById(R.id.labelImageView);
            viewHolder.titleCountLabel = (TextView) convertView.findViewById(R.id.titleCountLabel);
            viewHolder.titleTextLabel = (TextView) convertView.findViewById(R.id.titleTextLabel);
            viewHolder.descriptionLabel = (TextView) convertView.findViewById(R.id.descriptionLabel);
            viewHolder.dateLabel = (TextView) convertView.findViewById(R.id.dateLabel);
            viewHolder.couponCellLayout = (LinearLayout) convertView.findViewById(R.id.couponCellLayout);
            viewHolder.titleLabel = (TextView) convertView.findViewById(R.id.titleLabel);
            viewHolder.usePlaceLabel = (TextView) convertView.findViewById(R.id.usePlaceLabel);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        viewHolder.titleLabel.setTextColor(Color.rgb(63, 65, 72));
        viewHolder.titleTextLabel.setTextColor(Color.rgb(63, 65, 72));
        viewHolder.titleCountLabel.setTextColor(Color.rgb(63, 65, 72));
        viewHolder.dateLabel.setTextColor(Color.rgb(126, 132, 149));
        viewHolder.descriptionLabel.setTextColor(Color.parseColor("#b23f4148"));
        viewHolder.usePlaceLabel.setTextColor(Color.parseColor("#b23f4148"));
        viewHolder.couponCellLayout.setBackgroundResource(R.drawable.coupon_cell_bg);
        CouponDetailModel model = this.mCouponModels.get(position);
        viewHolder.titleLabel.setText(model.getCoupon_name());
        viewHolder.usePlaceLabel.setText("\ucfe0\ud3f0\uc0ac\uc6a9\ucc98 : " + model.getUsable_partner_name());
        viewHolder.descriptionLabel.setText(FormatUtil.onDecimalFormat(model.getMin_condition()) + "\uc6d0 \uc774\uc0c1 \uacb0\uc81c\uc2dc, \uc571\uacb0\uc81c\uace0\uac1d\uc5d0 \ud55c\ud568");
        viewHolder.titleCountLabel.setText(FormatUtil.onDecimalFormat(model.getDiscount_value()));
        if (model.getCoupon_type().equals("10")) {
            viewHolder.titleTextLabel.setText("\uc6d0 \ud560\uc778");
        } else {
            viewHolder.titleTextLabel.setText("% \ud560\uc778");
        }
        String dateLabel = "\uc720\ud6a8\uae30\uac04 : ~ " + model.getExpire_date() + "\uae4c\uc9c0";
        if (model.getCoupon_status().equals("00")) {
            viewHolder.dateLabel.setText(dateLabel);
            if (model.getLimit_yn().equals("Y")) {
                viewHolder.labelImageView.setImageResource(R.drawable.img_coupon_limit);
            } else {
                viewHolder.labelImageView.setImageResource(R.drawable.img_coupon_useable);
            }
        } else if (model.getCoupon_status().equals("10")) {
            viewHolder.dateLabel.setText(dateLabel + "(\uc0ac\uc6a9\uc644\ub8cc)");
            viewHolder.labelImageView.setImageResource(R.drawable.img_coupon_used);
            viewHolder.titleLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.titleTextLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.titleCountLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.dateLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.descriptionLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.usePlaceLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.couponCellLayout.setBackgroundResource(R.drawable.coupon_unused_cell_bg);
        } else {
            viewHolder.dateLabel.setText(dateLabel + "(\uae30\uac04\ub9cc\ub8cc)");
            viewHolder.labelImageView.setImageResource(R.drawable.img_coupon_unused);
            viewHolder.titleLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.titleTextLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.titleCountLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.dateLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.descriptionLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.usePlaceLabel.setTextColor(Color.rgb(208, 211, 218));
            viewHolder.couponCellLayout.setBackgroundResource(R.drawable.coupon_unused_cell_bg);
        }
        return convertView;
    }

    public void setData(ArrayList<CouponDetailModel> models) {
        this.mCouponModels = models;
        notifyDataSetChanged();
    }
}