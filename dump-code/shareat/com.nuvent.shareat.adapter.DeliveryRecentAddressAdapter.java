package com.nuvent.shareat.adapter;

import android.content.Context;
import android.support.v7.widget.RecyclerView.Adapter;
import android.support.v7.widget.RecyclerView.ViewHolder;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressRecentModel;
import java.util.ArrayList;

public class DeliveryRecentAddressAdapter extends Adapter<RecentAddressHolder> {
    private LayoutInflater inflater = null;
    /* access modifiers changed from: private */
    public AdapterClickListener mAdapterClickListener;
    private AdapterPositionState mAdapterPositionState;
    private Context mContext;
    private ArrayList<DeliveryShippingAddressRecentModel> models = new ArrayList<>();

    public interface AdapterClickListener {
        void onCheckedRecentAddress(int i, boolean z);
    }

    public interface AdapterPositionState {
        void onCurrentPosition(int i, RecentAddressHolder recentAddressHolder);
    }

    public class RecentAddressHolder extends ViewHolder {
        /* access modifiers changed from: private */
        public CheckBox checkValue;
        /* access modifiers changed from: private */
        public TextView fullAddress;
        private LinearLayout itemLayout;
        /* access modifiers changed from: private */
        public TextView receiverName;
        /* access modifiers changed from: private */
        public TextView receiverPhoneNumber;

        public RecentAddressHolder(View itemView) {
            super(itemView);
            this.itemLayout = (LinearLayout) itemView.findViewById(R.id.item_layout);
            this.fullAddress = (TextView) itemView.findViewById(R.id.full_address);
            this.receiverName = (TextView) itemView.findViewById(R.id.receiver_name);
            this.receiverPhoneNumber = (TextView) itemView.findViewById(R.id.receiver_phone_number);
            this.checkValue = (CheckBox) itemView.findViewById(R.id.check_value);
        }

        public LinearLayout getItemLayout() {
            return this.itemLayout;
        }
    }

    public void addAdapterPositionState(AdapterPositionState adapterPositionState) {
        this.mAdapterPositionState = adapterPositionState;
    }

    public void addAdapterClickListener(AdapterClickListener listener) {
        this.mAdapterClickListener = listener;
    }

    public DeliveryRecentAddressAdapter(Context context, ArrayList<DeliveryShippingAddressRecentModel> data) {
        this.mContext = context;
        this.models = data;
        this.inflater = LayoutInflater.from(context);
    }

    public void onBindViewHolder(RecentAddressHolder holder, int position) {
        DeliveryShippingAddressRecentModel recentAddress = this.models.get(position);
        final int currentPosition = position;
        String receiverName = recentAddress.getReceiveName();
        String fullAddress = recentAddress.getAddress() + " " + recentAddress.getAddressRest();
        String receiverPhoneNumber = recentAddress.getReceivePhone();
        holder.receiverName.setText(receiverName);
        holder.fullAddress.setText(fullAddress);
        holder.receiverPhoneNumber.setText(receiverPhoneNumber);
        holder.checkValue.setOnCheckedChangeListener(new OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (DeliveryRecentAddressAdapter.this.mAdapterClickListener != null) {
                    DeliveryRecentAddressAdapter.this.mAdapterClickListener.onCheckedRecentAddress(currentPosition, isChecked);
                }
            }
        });
        onPosition(position, holder);
    }

    private void onPosition(int position, RecentAddressHolder holder) {
        if (this.mAdapterPositionState != null) {
            this.mAdapterPositionState.onCurrentPosition(position, holder);
        }
    }

    public int getItemCount() {
        if (this.models == null) {
            return 0;
        }
        return this.models.size();
    }

    public DeliveryShippingAddressRecentModel getItem(int position) {
        if (this.models == null) {
            return null;
        }
        return this.models.get(position);
    }

    public RecentAddressHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        return new RecentAddressHolder(this.inflater.inflate(R.layout.delivery_recent_address_item, parent, false));
    }
}