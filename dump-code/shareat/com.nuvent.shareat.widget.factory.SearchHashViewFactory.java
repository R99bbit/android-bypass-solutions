package com.nuvent.shareat.widget.factory;

import android.content.Context;
import android.view.View;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.HashModel;

public class SearchHashViewFactory {
    public static View createView(Context context, HashModel model) {
        View convertView = View.inflate(context, R.layout.cell_search_hash, null);
        ((TextView) convertView.findViewById(R.id.titleLabel)).setText(model.getTagName());
        ((TextView) convertView.findViewById(R.id.countLabel)).setText(model.getTagCount() + context.getResources().getString(R.string.HASHRESULT_CELL_COUNT));
        return convertView;
    }
}