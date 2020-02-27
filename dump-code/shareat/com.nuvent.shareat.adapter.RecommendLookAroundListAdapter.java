package com.nuvent.shareat.adapter;

import android.content.Context;
import android.support.v7.widget.RecyclerView.Adapter;
import android.support.v7.widget.RecyclerView.ViewHolder;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.RecommendLookAroundDetailModel;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class RecommendLookAroundListAdapter extends Adapter<RecommendLookAroundViewHolder> {
    private LayoutInflater inflater = null;
    private AdapterPositionState mAdapterPositionState;
    private Context mContext;
    private ArrayList<RecommendLookAroundDetailModel> mRecommendLookAroundDetailModel = new ArrayList<>();

    public interface AdapterPositionState {
        void onCurrentPosition(int i, RecommendLookAroundViewHolder recommendLookAroundViewHolder);
    }

    public class RecommendLookAroundViewHolder extends ViewHolder {
        private LinearLayout itemLayout;
        /* access modifiers changed from: private */
        public TextView reCommendSubTitle;
        /* access modifiers changed from: private */
        public TextView reCommendTitle;
        /* access modifiers changed from: private */
        public ImageView recommendImageView;

        public RecommendLookAroundViewHolder(View itemView) {
            super(itemView);
            this.itemLayout = (LinearLayout) itemView.findViewById(R.id.itemLayout);
            this.recommendImageView = (ImageView) itemView.findViewById(R.id.recommendImageView);
            this.reCommendTitle = (TextView) itemView.findViewById(R.id.reCommendTitle);
            this.reCommendSubTitle = (TextView) itemView.findViewById(R.id.reCommendSubTitle);
        }

        public LinearLayout getItemLayout() {
            return this.itemLayout;
        }
    }

    public void addAdapterPositionState(AdapterPositionState adapterPositionState) {
        this.mAdapterPositionState = adapterPositionState;
    }

    public RecommendLookAroundListAdapter(Context context, ArrayList<RecommendLookAroundDetailModel> model) {
        this.mContext = context;
        this.mRecommendLookAroundDetailModel = model;
        this.inflater = LayoutInflater.from(context);
    }

    public void onBindViewHolder(RecommendLookAroundViewHolder holder, int position) {
        RecommendLookAroundDetailModel recommendLookAroundDetailModel = this.mRecommendLookAroundDetailModel.get(position);
        String imageUrl = recommendLookAroundDetailModel.getImage_path();
        String title = recommendLookAroundDetailModel.getTitle();
        String subTitle = recommendLookAroundDetailModel.getSub_title();
        ImageDisplay.getInstance().displayImageLoad(imageUrl, holder.recommendImageView);
        holder.reCommendTitle.setText(title);
        holder.reCommendSubTitle.setText(subTitle);
        onPosition(position, holder);
    }

    private void onPosition(int position, RecommendLookAroundViewHolder holder) {
        if (this.mAdapterPositionState != null) {
            this.mAdapterPositionState.onCurrentPosition(position, holder);
        }
    }

    public int getItemCount() {
        if (this.mRecommendLookAroundDetailModel == null) {
            return 0;
        }
        return this.mRecommendLookAroundDetailModel.size();
    }

    public RecommendLookAroundDetailModel getItem(int position) {
        if (this.mRecommendLookAroundDetailModel == null) {
            return null;
        }
        return this.mRecommendLookAroundDetailModel.get(position);
    }

    public RecommendLookAroundViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        return new RecommendLookAroundViewHolder(this.inflater.inflate(R.layout.main_list_recommend_look_around_item, parent, false));
    }
}