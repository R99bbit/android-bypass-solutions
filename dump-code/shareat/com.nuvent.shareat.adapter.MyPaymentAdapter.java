package com.nuvent.shareat.adapter;

import android.content.Context;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.MyPaymentModel;
import com.nuvent.shareat.model.payment.MyPaymentsHistoryDetailModel;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class MyPaymentAdapter extends BaseAdapter {
    private Context mContext;
    private ArrayList<MyPaymentModel> mMyPaymentModels = new ArrayList<>();

    class ViewHolder {
        TextView card;
        TextView cardNum;
        TextView date;
        TextView detail;
        TextView discount;
        ImageView[] myPaymentNimg;
        TextView[] myPaymentNname;
        TextView partnerName;
        TextView pay;
        RelativeLayout payPeopleLayout;
        TextView paymentCancleDate;
        View paymentCancleLayout;
        View paymentCellLayout;
        View people;
        TextView peopleCount;
        View peopleIcon;
        View peopleLayout;
        View won;

        ViewHolder() {
        }
    }

    public MyPaymentAdapter(Context context) {
        this.mContext = context;
    }

    public int getCount() {
        return this.mMyPaymentModels.size();
    }

    public Object getItem(int position) {
        return this.mMyPaymentModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup viewGroup) {
        ViewHolder viewHolder;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = LayoutInflater.from(this.mContext).inflate(R.layout.cell_my_payment, viewGroup, false);
            viewHolder.cardNum = (TextView) convertView.findViewById(R.id.cardNumLabel);
            viewHolder.payPeopleLayout = (RelativeLayout) convertView.findViewById(R.id.payPeopleLayout);
            viewHolder.paymentCellLayout = convertView.findViewById(R.id.paymentCellLayout);
            viewHolder.date = (TextView) convertView.findViewById(R.id.date);
            viewHolder.pay = (TextView) convertView.findViewById(R.id.pay);
            viewHolder.partnerName = (TextView) convertView.findViewById(R.id.partner_name);
            viewHolder.peopleCount = (TextView) convertView.findViewById(R.id.people_count);
            viewHolder.people = convertView.findViewById(R.id.people);
            viewHolder.card = (TextView) convertView.findViewById(R.id.card);
            viewHolder.detail = (TextView) convertView.findViewById(R.id.detail);
            viewHolder.discount = (TextView) convertView.findViewById(R.id.discount);
            viewHolder.peopleLayout = convertView.findViewById(R.id.people_layout);
            viewHolder.paymentCancleDate = (TextView) convertView.findViewById(R.id.payment_cancel_date);
            viewHolder.paymentCancleLayout = convertView.findViewById(R.id.payment_cancle_layout);
            viewHolder.won = convertView.findViewById(R.id.won);
            viewHolder.peopleIcon = convertView.findViewById(R.id.people_icon);
            viewHolder.myPaymentNimg = new ImageView[]{(ImageView) convertView.findViewById(R.id.mypayment_n_1_img), (ImageView) convertView.findViewById(R.id.mypayment_n_2_img), (ImageView) convertView.findViewById(R.id.mypayment_n_3_img), (ImageView) convertView.findViewById(R.id.mypayment_n_4_img), (ImageView) convertView.findViewById(R.id.mypayment_n_5_img), (ImageView) convertView.findViewById(R.id.mypayment_n_6_img)};
            viewHolder.myPaymentNname = new TextView[]{(TextView) convertView.findViewById(R.id.mypayment_n_1_name), (TextView) convertView.findViewById(R.id.mypayment_n_2_name), (TextView) convertView.findViewById(R.id.mypayment_n_3_name), (TextView) convertView.findViewById(R.id.mypayment_n_4_name), (TextView) convertView.findViewById(R.id.mypayment_n_5_name), (TextView) convertView.findViewById(R.id.mypayment_n_6_name)};
            for (int i = 0; i < viewHolder.myPaymentNimg.length; i++) {
                viewHolder.myPaymentNimg[i].setVisibility(8);
                viewHolder.myPaymentNname[i].setVisibility(8);
            }
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        MyPaymentModel model = this.mMyPaymentModels.get(position);
        viewHolder.date.setText(model.getDateText());
        viewHolder.pay.setText(model.getRealPay(String.valueOf(model.card_pay_amt)));
        viewHolder.partnerName.setText(model.partner_name1);
        viewHolder.peopleCount.setText(model.getPeopleCount());
        viewHolder.card.setText(model.card_name + "-");
        viewHolder.cardNum.setText(model.card_no);
        viewHolder.detail.setText(" " + model.getDetailText());
        viewHolder.discount.setText(" " + model.dc_rate + this.mContext.getResources().getString(R.string.MY_PATMENT_DC_RATE));
        viewHolder.paymentCancleDate.setText(TextUtils.isEmpty(model.cancel_date_text) ? "" : model.cancel_date_text);
        if (model.isOpen) {
            viewHolder.peopleLayout.setVisibility(0);
            if (model.result_list.size() > 0) {
                MyPaymentsHistoryDetailModel nUser = model.result_list.get(0);
                viewHolder.myPaymentNimg[0].setVisibility(0);
                viewHolder.myPaymentNname[0].setVisibility(0);
                if (!TextUtils.isEmpty(nUser.profile)) {
                    ImageDisplay.getInstance().displayImageLoad(nUser.profile, viewHolder.myPaymentNimg[0]);
                } else {
                    viewHolder.myPaymentNimg[0].setImageResource(R.drawable.empty_profile_circle_2);
                }
                viewHolder.myPaymentNname[0].setText(nUser.pay_user_name);
            }
        } else {
            viewHolder.peopleLayout.setVisibility(8);
        }
        boolean isSelector = TextUtils.isEmpty(model.cancel_date_text);
        viewHolder.paymentCancleLayout.setVisibility(isSelector ? 8 : 0);
        viewHolder.paymentCellLayout.setSelected(!isSelector);
        viewHolder.payPeopleLayout.setBackgroundResource(isSelector ? R.drawable.my_payment_people_on : R.drawable.my_payment_people_off);
        viewHolder.date.setSelected(isSelector);
        viewHolder.pay.setSelected(isSelector);
        viewHolder.partnerName.setSelected(isSelector);
        viewHolder.peopleCount.setSelected(isSelector);
        viewHolder.card.setSelected(isSelector);
        viewHolder.cardNum.setSelected(isSelector);
        viewHolder.won.setSelected(isSelector);
        viewHolder.peopleIcon.setSelected(isSelector);
        return convertView;
    }

    public void setData(ArrayList<MyPaymentModel> models) {
        this.mMyPaymentModels = models;
        notifyDataSetChanged();
    }
}