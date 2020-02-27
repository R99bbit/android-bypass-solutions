package com.nuvent.shareat.activity.picker;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.AsyncTask;
import android.os.Bundle;
import android.provider.MediaStore.Images.Media;
import android.provider.MediaStore.Images.Thumbnails;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.BaseAdapter;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.model.ImageFolderModel;
import com.nuvent.shareat.util.BitmapHelper;
import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class PickerFolderActivity extends MainActionBarActivity {
    public static final int REQUEST_CODE_IMAGE_PICKER = 1;
    private GridView folderLists;
    private ImageAdapter mAdapter;
    /* access modifiers changed from: private */
    public List<ImageFolderModel> mFolders;

    public class ImageAdapter extends BaseAdapter {
        private Context mContext;

        public ImageAdapter(Context context) {
            this.mContext = context;
        }

        public int getCount() {
            if (PickerFolderActivity.this.mFolders == null) {
                return 0;
            }
            return PickerFolderActivity.this.mFolders.size();
        }

        public Object getItem(int position) {
            return PickerFolderActivity.this.mFolders.get(position);
        }

        public long getItemId(int position) {
            return (long) position;
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            if (convertView == null) {
                convertView = PickerFolderActivity.this.getLayoutInflater().inflate(R.layout.cell_image_folder, parent, false);
                holder = new ViewHolder();
                holder.FolderName = (TextView) convertView.findViewById(R.id.review_folder_item_name);
                holder.FolderThum = (ImageView) convertView.findViewById(R.id.review_folder_item_img);
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }
            int pos = position;
            ImageFolderModel folderVo = (ImageFolderModel) PickerFolderActivity.this.mFolders.get(pos);
            holder.FolderThum.setImageResource(R.drawable.review_album_group);
            if (folderVo.FolderThum == null) {
                new ImageLoadTask(this.mContext, holder.FolderThum, pos).execute(new ImageFolderModel[]{folderVo});
            } else {
                holder.FolderThum.setImageBitmap(folderVo.FolderThum);
            }
            holder.FolderName.setText(folderVo.FolderName);
            convertView.setTag(holder);
            return convertView;
        }
    }

    class ImageLoadTask extends AsyncTask<ImageFolderModel, Void, ImageFolderModel> {
        private int idx;
        private Context mContext;
        private Rect rectSize;
        private ImageView rowImg;

        public ImageLoadTask(Context context, ImageView img, int idx2) {
            this.mContext = context;
            this.rowImg = img;
            this.idx = idx2;
            MarginLayoutParams layoutParams = (MarginLayoutParams) img.getLayoutParams();
            this.rectSize = new Rect(0, 0, Math.abs(layoutParams.width), Math.abs(layoutParams.height));
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(ImageFolderModel vo) {
            this.rowImg.setImageBitmap(vo.FolderThum);
            PickerFolderActivity.this.mFolders.set(this.idx, vo);
        }

        /* access modifiers changed from: protected */
        public ImageFolderModel doInBackground(ImageFolderModel... params) {
            ImageFolderModel vo = params[0];
            try {
                if (this.mContext != null) {
                    int angel = BitmapHelper.getBitmapAngle(vo.FilePath);
                    Bitmap folderThum = Thumbnails.getThumbnail(this.mContext.getContentResolver(), (long) vo.idx, 1, null);
                    if (angel > 0) {
                        folderThum = BitmapHelper.getRotatedBitmap(folderThum, (float) angel);
                    }
                    vo.FolderThum = BitmapHelper.getRoundedCornerBitmap(this.mContext, R.drawable.review_album_group, this.rectSize, BitmapHelper.getSquareBitmap(folderThum));
                }
            } catch (Exception e) {
            }
            return vo;
        }
    }

    static class ViewHolder {
        TextView FolderCnt;
        TextView FolderName;
        ImageView FolderThum;

        ViewHolder() {
        }
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (1 == requestCode && -1 == resultCode) {
            Intent result = new Intent();
            result.putExtra("resultData", data.getSerializableExtra("resultData"));
            setResult(-1, result);
            finish();
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_image_folder, 2);
        setTitle("\uc804\uccb4");
        showFavoriteButton(false);
        showSubActionbar();
        this.folderLists = (GridView) findViewById(R.id.pay_n_gallery);
        this.mAdapter = new ImageAdapter(this);
        this.folderLists.setAdapter(this.mAdapter);
        this.folderLists.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                String selectedFolder = ((ImageFolderModel) PickerFolderActivity.this.mFolders.get(position)).FolderName;
                Intent intent = new Intent(PickerFolderActivity.this, PickerImageActivity.class);
                intent.putExtra("currentSize", PickerFolderActivity.this.getIntent().getIntExtra("currentSize", 0));
                intent.putExtra("title", selectedFolder);
                intent.putExtra("selectedModels", PickerFolderActivity.this.getIntent().getSerializableExtra("selectedModels"));
                PickerFolderActivity.this.animActivityForResult(intent, 1, R.anim.slide_from_right, R.anim.slide_out_to_left);
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        this.mFolders = getImagesFolders();
        this.mAdapter.notifyDataSetChanged();
    }

    public List<ImageFolderModel> getImagesFolders() {
        ArrayList<ImageFolderModel> all = new ArrayList<>();
        Cursor cursor = getContentResolver().query(Media.EXTERNAL_CONTENT_URI, new String[]{"_id", "_data", "bucket_display_name", "date_added"}, null, null, "date_added desc");
        int column_index = cursor.getColumnIndex("_id");
        int column_index_folder_name = cursor.getColumnIndex("bucket_display_name");
        int column_index_data = cursor.getColumnIndexOrThrow("_data");
        while (cursor.moveToNext()) {
            ImageFolderModel model = new ImageFolderModel();
            model.idx = cursor.getInt(column_index);
            model.FolderName = cursor.getString(column_index_folder_name);
            model.FilePath = cursor.getString(column_index_data);
            if (all.size() == 0) {
                all.add(model);
            } else {
                Boolean isFolder = Boolean.valueOf(false);
                Iterator<ImageFolderModel> it = all.iterator();
                while (true) {
                    if (it.hasNext()) {
                        if (it.next().FolderName.equals(model.FolderName)) {
                            isFolder = Boolean.valueOf(true);
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if (!isFolder.booleanValue()) {
                    all.add(model);
                }
            }
        }
        cursor.close();
        Collections.sort(all, new Comparator<ImageFolderModel>() {
            private final Collator collator = Collator.getInstance();

            public int compare(ImageFolderModel object1, ImageFolderModel object2) {
                return this.collator.compare(object1.FolderName, object2.FolderName);
            }
        });
        return all;
    }
}