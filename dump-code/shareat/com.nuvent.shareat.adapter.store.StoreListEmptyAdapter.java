package com.nuvent.shareat.adapter.store;

import android.content.Context;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import com.nuvent.shareat.R;
import com.nuvent.shareat.adapter.RecommendLookAroundListAdapter;
import com.nuvent.shareat.adapter.RecommendLookAroundListAdapter.AdapterPositionState;
import com.nuvent.shareat.adapter.RecommendLookAroundListAdapter.RecommendLookAroundViewHolder;
import com.nuvent.shareat.adapter.RecyclerItemClickListener;
import com.nuvent.shareat.adapter.RecyclerItemClickListener.OnItemClickListener;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.model.RecommendLookAroundDetailModel;
import com.nuvent.shareat.model.RecommendLookAroundModel;
import com.nuvent.shareat.util.GAEvent;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import net.xenix.android.widget.FontTextView;

public class StoreListEmptyAdapter extends BaseAdapter {
    private LayoutInflater inflater = null;
    /* access modifiers changed from: private */
    public LayoutParams mAdapterLayoutParams;
    /* access modifiers changed from: private */
    public Context mContext;
    /* access modifiers changed from: private */
    public OnStoreListEmptyAdapterListener mListener;
    private RecommendLookAroundModel mRecommendLookAroundModel = null;
    /* access modifiers changed from: private */
    public RecommendLookAroundListAdapter mRecommendationLookAroundAdapter;
    private ViewHolder viewHolder = null;

    public interface OnStoreListEmptyAdapterListener {
        void otherRegionBtnClick();
    }

    public class ViewHolder {
        public ImageView otherRegionBtn;
        public FontTextView pagerTitle;
        public RecyclerView recommendLookAroundListView;

        public ViewHolder() {
        }
    }

    public StoreListEmptyAdapter(Context context, RecommendLookAroundModel model) {
        this.mContext = context;
        this.mRecommendLookAroundModel = model;
        this.inflater = LayoutInflater.from(context);
    }

    public void setListener(OnStoreListEmptyAdapterListener listener) {
        this.mListener = listener;
    }

    public void setRecommendLookAroundModel(RecommendLookAroundModel model) {
        this.mRecommendLookAroundModel = model;
    }

    public void notifyDataSetChanged() {
        super.notifyDataSetChanged();
    }

    public int getCount() {
        return 1;
    }

    public Object getItem(int position) {
        return this.mRecommendLookAroundModel;
    }

    public long getItemId(int position) {
        return 0;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        if (convertView == null) {
            this.viewHolder = new ViewHolder();
            convertView = this.inflater.inflate(R.layout.fragment_main_empty, null);
            this.viewHolder.otherRegionBtn = (ImageView) convertView.findViewById(R.id.otherRegionBtn);
            this.viewHolder.pagerTitle = (FontTextView) convertView.findViewById(R.id.pagerTitle);
            this.viewHolder.recommendLookAroundListView = (RecyclerView) convertView.findViewById(R.id.recommendLookAroundListView);
            convertView.setTag(this.viewHolder);
        } else {
            this.viewHolder = (ViewHolder) convertView.getTag();
        }
        this.viewHolder.otherRegionBtn.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (StoreListEmptyAdapter.this.mListener != null) {
                    StoreListEmptyAdapter.this.mListener.otherRegionBtnClick();
                }
            }
        });
        this.viewHolder.pagerTitle.setText(this.mRecommendLookAroundModel.getHead_title());
        this.mRecommendationLookAroundAdapter = new RecommendLookAroundListAdapter(convertView.getContext(), this.mRecommendLookAroundModel.getResult_list());
        LinearLayoutManager llm = new LinearLayoutManager(this.mContext);
        llm.setOrientation(0);
        this.viewHolder.recommendLookAroundListView.setLayoutManager(llm);
        this.viewHolder.recommendLookAroundListView.setAdapter(this.mRecommendationLookAroundAdapter);
        this.viewHolder.recommendLookAroundListView.addOnItemTouchListener(new RecyclerItemClickListener(this.mContext, this.viewHolder.recommendLookAroundListView, new OnItemClickListener() {
            public void onItemClick(View view, int position) {
                if (StoreListEmptyAdapter.this.mRecommendationLookAroundAdapter != null) {
                    RecommendLookAroundDetailModel model = StoreListEmptyAdapter.this.mRecommendationLookAroundAdapter.getItem(position);
                    GAEvent.onGaEvent(StoreListEmptyAdapter.this.mContext.getResources().getString(R.string.ga_empty_store), StoreListEmptyAdapter.this.mContext.getResources().getString(R.string.ga_item_click), model.getTitle() + EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR + String.valueOf(position));
                    String schemeUrl = model.getScheme_url();
                    new CustomSchemeManager();
                    CustomSchemeManager.postSchemeAction(StoreListEmptyAdapter.this.mContext, schemeUrl);
                }
            }

            public void onItemLongClick(View view, int position) {
            }
        }));
        this.mAdapterLayoutParams = new LayoutParams(-2, -2);
        this.mRecommendationLookAroundAdapter.addAdapterPositionState(new AdapterPositionState() {
            public void onCurrentPosition(int position, RecommendLookAroundViewHolder holder) {
                LinearLayout itemLayout = holder.getItemLayout();
                if (position == 0) {
                    StoreListEmptyAdapter.this.mAdapterLayoutParams.rightMargin = 0;
                    StoreListEmptyAdapter.this.mAdapterLayoutParams.leftMargin = ((int) StoreListEmptyAdapter.this.dpToPx(StoreListEmptyAdapter.this.mContext, 6)) + ((int) StoreListEmptyAdapter.this.dpToPx(StoreListEmptyAdapter.this.mContext, 17));
                    itemLayout.setLayoutParams(StoreListEmptyAdapter.this.mAdapterLayoutParams);
                } else if (position == StoreListEmptyAdapter.this.mRecommendationLookAroundAdapter.getItemCount() - 1) {
                    StoreListEmptyAdapter.this.mAdapterLayoutParams.rightMargin = (int) StoreListEmptyAdapter.this.dpToPx(StoreListEmptyAdapter.this.mContext, 17);
                    StoreListEmptyAdapter.this.mAdapterLayoutParams.leftMargin = (int) StoreListEmptyAdapter.this.dpToPx(StoreListEmptyAdapter.this.mContext, 17);
                    itemLayout.setLayoutParams(StoreListEmptyAdapter.this.mAdapterLayoutParams);
                } else {
                    StoreListEmptyAdapter.this.mAdapterLayoutParams.rightMargin = 0;
                    StoreListEmptyAdapter.this.mAdapterLayoutParams.leftMargin = (int) StoreListEmptyAdapter.this.dpToPx(StoreListEmptyAdapter.this.mContext, 17);
                    itemLayout.setLayoutParams(StoreListEmptyAdapter.this.mAdapterLayoutParams);
                }
            }
        });
        return convertView;
    }

    /* access modifiers changed from: private */
    public float dpToPx(Context context, int dp) {
        return (float) ((context.getResources().getDisplayMetrics().densityDpi / 160) * dp);
    }
}