package com.nuvent.shareat.adapter.interest;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.ProfileStoreModel;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class ZzimAdapter extends BaseAdapter {
    private Context mContext;
    private LayoutInflater mLayoutInflater;
    private ArrayList<ProfileStoreModel> mZzimModels = new ArrayList<>();

    class ViewHolder {
        View bottom;
        TextView category;
        ImageView img;
        View star;
        TextView storeAddrDist;
        TextView storeName;
        View top;

        ViewHolder() {
        }
    }

    public ZzimAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return this.mZzimModels.size();
    }

    public Object getItem(int position) {
        return this.mZzimModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder;
        int i;
        int i2 = 4;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = this.mLayoutInflater.inflate(R.layout.cell_interest_zzim, null);
            viewHolder.top = convertView.findViewById(R.id.top);
            viewHolder.bottom = convertView.findViewById(R.id.bottom);
            viewHolder.img = (ImageView) convertView.findViewById(R.id.img);
            viewHolder.star = convertView.findViewById(R.id.star);
            viewHolder.star.setVisibility(0);
            viewHolder.storeName = (TextView) convertView.findViewById(R.id.store_name);
            viewHolder.storeAddrDist = (TextView) convertView.findViewById(R.id.store_addr_dist);
            viewHolder.category = (TextView) convertView.findViewById(R.id.category);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        ProfileStoreModel model = this.mZzimModels.get(position);
        View view = viewHolder.top;
        if (position == 0) {
            i = 4;
        } else {
            i = 0;
        }
        view.setVisibility(i);
        View view2 = viewHolder.bottom;
        if (position != this.mZzimModels.size() - 1) {
            i2 = 0;
        }
        view2.setVisibility(i2);
        String imageUrl = null;
        if (0 == 0) {
            if (model.getImg_thumbnail_url() != null) {
                imageUrl = model.getImg_thumbnail_url();
            } else if (model.getImg_url() != null) {
                imageUrl = model.getImg_url();
            } else {
                imageUrl = model.getListImg();
            }
        }
        ImageDisplay.getInstance().displayImageLoadRoundStore(imageUrl, viewHolder.img, this.mContext.getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_15OPX));
        viewHolder.storeName.setText(model.getPartnerName1());
        viewHolder.storeAddrDist.setText(model.getStoreAddrDist());
        viewHolder.category.setText(model.getCategoryName());
        return convertView;
    }

    public void setData(ArrayList<ProfileStoreModel> models) {
        this.mZzimModels = models;
        notifyDataSetChanged();
    }
}