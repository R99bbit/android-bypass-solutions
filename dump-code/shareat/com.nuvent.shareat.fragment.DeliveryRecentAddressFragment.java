package com.nuvent.shareat.fragment;

import android.annotation.SuppressLint;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.support.v4.content.ContextCompat;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.RecyclerView.ItemDecoration;
import android.support.v7.widget.RecyclerView.LayoutParams;
import android.support.v7.widget.RecyclerView.State;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.adapter.DeliveryRecentAddressAdapter;
import com.nuvent.shareat.adapter.DeliveryRecentAddressAdapter.AdapterClickListener;
import com.nuvent.shareat.adapter.DeliveryRecentAddressAdapter.RecentAddressHolder;
import com.nuvent.shareat.adapter.RecyclerItemClickListener;
import com.nuvent.shareat.adapter.RecyclerItemClickListener.OnItemClickListener;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressRecentModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class DeliveryRecentAddressFragment extends Fragment {
    private ArrayList<DeliveryShippingAddressRecentModel> deliveryShippingAddressRecentModels;
    /* access modifiers changed from: private */
    public RecyclerView recentAddressRecyclerView;
    private View recentAddressView;

    public class RecyclerDecoration extends ItemDecoration {
        private Drawable line;
        private final Paint paint = new Paint();

        public RecyclerDecoration(Drawable line2) {
            this.line = line2;
            this.paint.setColor(Color.parseColor("#eeeff2"));
            this.paint.setStrokeWidth(TypedValue.applyDimension(1, 1.0f, DeliveryRecentAddressFragment.this.getResources().getDisplayMetrics()));
        }

        public void getItemOffsets(Rect outRect, View view, RecyclerView parent, State state) {
            if (((LayoutParams) view.getLayoutParams()).getViewAdapterPosition() < state.getItemCount()) {
                outRect.set(0, 0, 0, (int) this.paint.getStrokeWidth());
            } else {
                outRect.setEmpty();
            }
        }

        public void onDraw(Canvas c, RecyclerView parent, State state) {
            int offset = (int) (this.paint.getStrokeWidth() / 2.0f);
            for (int i = 0; i < parent.getChildCount(); i++) {
                View view = parent.getChildAt(i);
                if (((LayoutParams) view.getLayoutParams()).getViewAdapterPosition() < state.getItemCount()) {
                    c.drawLine((float) view.getLeft(), (float) (view.getBottom() + offset), (float) view.getRight(), (float) (view.getBottom() + offset), this.paint);
                }
            }
        }
    }

    public DeliveryRecentAddressFragment() {
    }

    @SuppressLint({"ValidFragment"})
    public DeliveryRecentAddressFragment(ArrayList<DeliveryShippingAddressRecentModel> models) {
        this.deliveryShippingAddressRecentModels = models;
    }

    @Nullable
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        this.recentAddressView = inflater.inflate(R.layout.fragment_delivery_recent_address_layout, container, false);
        if (this.deliveryShippingAddressRecentModels == null || this.deliveryShippingAddressRecentModels.size() <= 0) {
            this.recentAddressView.findViewById(R.id.empty_layout).setVisibility(0);
            this.recentAddressView.findViewById(R.id.recent_address_list).setVisibility(8);
        } else {
            setData(this.deliveryShippingAddressRecentModels);
        }
        return this.recentAddressView;
    }

    public Map<String, String> getReceiverInfo() {
        Map<String, String> data = new HashMap<>();
        if (this.deliveryShippingAddressRecentModels.size() <= 0) {
            data.put("receiveName", "");
            data.put("address", "");
            data.put("addressRest", "");
            data.put("receivePhone", "");
            data.put("zipCode", "");
            data.put("requestMessage", "");
        } else {
            DeliveryRecentAddressAdapter addressAdapter = (DeliveryRecentAddressAdapter) this.recentAddressRecyclerView.getAdapter();
            int checkedPosition = 0;
            int i = 0;
            while (true) {
                if (i >= addressAdapter.getItemCount()) {
                    break;
                } else if (true == ((CheckBox) ((RecentAddressHolder) this.recentAddressRecyclerView.findViewHolderForLayoutPosition(i)).getItemLayout().findViewById(R.id.check_value)).isChecked()) {
                    checkedPosition = i;
                    break;
                } else {
                    i++;
                }
            }
            DeliveryShippingAddressRecentModel deliveryShippingAddressRecentModel = addressAdapter.getItem(checkedPosition);
            data.put("receiveName", deliveryShippingAddressRecentModel.getReceiveName());
            data.put("address", deliveryShippingAddressRecentModel.getAddress());
            data.put("addressRest", deliveryShippingAddressRecentModel.getAddressRest());
            data.put("receivePhone", deliveryShippingAddressRecentModel.getReceivePhone());
            data.put("zipCode", deliveryShippingAddressRecentModel.getZipCode());
            data.put("requestMessage", ((TextView) this.recentAddressView.findViewById(R.id.receiver_inquire)).getText().toString());
        }
        return data;
    }

    public void setData(ArrayList<DeliveryShippingAddressRecentModel> models) {
        this.deliveryShippingAddressRecentModels = models;
        this.recentAddressView.findViewById(R.id.empty_layout).setVisibility(8);
        this.recentAddressView.findViewById(R.id.recent_address_list).setVisibility(0);
        this.recentAddressRecyclerView = (RecyclerView) this.recentAddressView.findViewById(R.id.recent_address_list);
        this.recentAddressRecyclerView.addItemDecoration(new RecyclerDecoration(ContextCompat.getDrawable(getContext(), R.drawable.recycler_view_devide_line)));
        final DeliveryRecentAddressAdapter recentAddressAdapter = new DeliveryRecentAddressAdapter(getContext(), this.deliveryShippingAddressRecentModels);
        LinearLayoutManager llm = new LinearLayoutManager(getContext());
        llm.setOrientation(1);
        this.recentAddressRecyclerView.setLayoutManager(llm);
        this.recentAddressRecyclerView.setAdapter(recentAddressAdapter);
        this.recentAddressRecyclerView.addOnItemTouchListener(new RecyclerItemClickListener(getContext(), this.recentAddressRecyclerView, new OnItemClickListener() {
            public void onItemClick(View view, int position) {
                if (recentAddressAdapter != null) {
                    DeliveryShippingAddressRecentModel item = recentAddressAdapter.getItem(position);
                }
            }

            public void onItemLongClick(View view, int position) {
            }
        }));
        recentAddressAdapter.addAdapterClickListener(new AdapterClickListener() {
            public void onCheckedRecentAddress(int position, boolean isClick) {
                if (isClick) {
                    DeliveryRecentAddressAdapter addressAdapter = (DeliveryRecentAddressAdapter) DeliveryRecentAddressFragment.this.recentAddressRecyclerView.getAdapter();
                    for (int i = 0; i < addressAdapter.getItemCount(); i++) {
                        RecentAddressHolder recentAddressHolder = (RecentAddressHolder) DeliveryRecentAddressFragment.this.recentAddressRecyclerView.findViewHolderForLayoutPosition(i);
                        if (position != i) {
                            ((CheckBox) recentAddressHolder.getItemLayout().findViewById(R.id.check_value)).setChecked(false);
                        }
                    }
                }
            }
        });
    }
}