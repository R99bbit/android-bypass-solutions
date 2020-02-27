package com.nuvent.shareat.activity.picker;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Rect;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.provider.MediaStore.Images.Media;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.BaseAdapter;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.model.PickerImageModel;
import java.util.ArrayList;
import java.util.Iterator;
import net.xenix.util.ImageDisplay;

public class PickerImageActivity extends BaseActivity {
    private final int DEFAULT_IMG_CNT = 0;
    private final int MAX_IMG_CNT = 6;
    /* access modifiers changed from: private */
    public int mAllRegSelectedImgCnt = 6;
    private Boolean mAllRegedImgsState = Boolean.valueOf(false);
    private String mFolder;
    /* access modifiers changed from: private */
    public ImageAdapter mImageAdapter;
    /* access modifiers changed from: private */
    public ArrayList<PickerImageModel> mListOfAllImages = new ArrayList<>();
    /* access modifiers changed from: private */
    public int mSelectedImgCnt = 0;
    /* access modifiers changed from: private */
    public ArrayList<PickerImageModel> mSelectedModels = new ArrayList<>();

    public class ImageAdapter extends BaseAdapter {
        private Context mContext;
        private Rect rectSize;

        public ImageAdapter(Context context) {
            this.mContext = context;
        }

        public int getCount() {
            return PickerImageActivity.this.mListOfAllImages.size();
        }

        public PickerImageModel getItem(int position) {
            return (PickerImageModel) PickerImageActivity.this.mListOfAllImages.get(position);
        }

        public long getItemId(int position) {
            return (long) position;
        }

        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            PickerImageModel imgVo = (PickerImageModel) PickerImageActivity.this.mListOfAllImages.get(position);
            if (convertView == null) {
                convertView = PickerImageActivity.this.getLayoutInflater().inflate(R.layout.cell_image_viewer, parent, false);
                holder = new ViewHolder();
                holder.overlayImgChk = (RelativeLayout) convertView.findViewById(R.id.gallery_item_click_layout);
                holder.itemImg = (ImageView) convertView.findViewById(R.id.review_gallery_item_img);
                MarginLayoutParams layoutParams = (MarginLayoutParams) holder.itemImg.getLayoutParams();
                this.rectSize = new Rect(0, 0, Math.abs(layoutParams.width), Math.abs(layoutParams.height));
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }
            holder.itemImg.setImageResource(R.drawable.review_album_shadow);
            holder.overlayImgChk.setVisibility(imgVo.isSelected ? 0 : 8);
            ImageDisplay.getInstance().displayImageLoad("file:/" + imgVo.getImagePath(), holder.itemImg);
            convertView.setTag(holder);
            return convertView;
        }
    }

    static class ViewHolder {
        ImageView itemImg;
        RelativeLayout overlayImgChk;

        ViewHolder() {
        }
    }

    public void onBackPressed() {
        finish();
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickConfirm(View view) {
        Intent result = new Intent();
        result.putExtra("resultData", this.mSelectedModels);
        setResult(-1, result);
        finish();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_image_picker);
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        this.mFolder = getIntent().getStringExtra("title");
        this.mSelectedModels = (ArrayList) getIntent().getSerializableExtra("selectedModels");
        ((TextView) findViewById(R.id.titleLabel)).setText(this.mFolder);
        findViewById(R.id.review_gallery_save).setEnabled(false);
        GridView mImgGridView = (GridView) findViewById(R.id.pay_n_gallery);
        this.mImageAdapter = new ImageAdapter(this);
        mImgGridView.setAdapter(this.mImageAdapter);
        mImgGridView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                boolean z = true;
                PickerImageModel selectedImgVo = (PickerImageModel) PickerImageActivity.this.mListOfAllImages.get(position);
                selectedImgVo.isSelected = !selectedImgVo.isSelected;
                if (PickerImageActivity.this.mSelectedImgCnt < 0) {
                    PickerImageActivity.this.mSelectedImgCnt = 0;
                } else if (selectedImgVo.isSelected) {
                    PickerImageActivity.this.mSelectedImgCnt = PickerImageActivity.this.mSelectedImgCnt + 1;
                    if (PickerImageActivity.this.mSelectedImgCnt > PickerImageActivity.this.mAllRegSelectedImgCnt) {
                        PickerImageActivity.this.mSelectedImgCnt = PickerImageActivity.this.mAllRegSelectedImgCnt;
                        String msg = String.format(PickerImageActivity.this.getString(R.string.REVIEW_INSERT_IMG_MAX), new Object[]{Integer.valueOf(PickerImageActivity.this.mAllRegSelectedImgCnt)});
                        if (PickerImageActivity.this.mAllRegSelectedImgCnt != 6) {
                            msg = String.format(PickerImageActivity.this.getString(R.string.REVIEW_RE_INSERT_IMG_MAX), new Object[]{Integer.valueOf(PickerImageActivity.this.mAllRegSelectedImgCnt)});
                        }
                        Toast.makeText(PickerImageActivity.this, msg, 1).show();
                        if (selectedImgVo.isSelected) {
                            z = false;
                        }
                        selectedImgVo.isSelected = z;
                        return;
                    }
                    PickerImageActivity.this.mSelectedModels.add(selectedImgVo);
                } else {
                    PickerImageActivity.this.mSelectedImgCnt = PickerImageActivity.this.mSelectedImgCnt - 1;
                    PickerImageActivity.this.mSelectedModels.remove(selectedImgVo);
                }
                PickerImageActivity.this.mImageAdapter.notifyDataSetChanged();
                PickerImageActivity.this.onSelectedImgIdx(PickerImageActivity.this.mSelectedImgCnt);
            }
        });
        this.mListOfAllImages = getImagesPath();
        onSelectedImgIdx(this.mSelectedImgCnt);
        if (this.mSelectedModels != null) {
            this.mAllRegSelectedImgCnt -= getIntent().getIntExtra("currentSize", this.mSelectedModels.size());
        }
    }

    public ArrayList<PickerImageModel> getImagesPath() {
        ArrayList<PickerImageModel> listOfAllImages = new ArrayList<>();
        Cursor cursor = getContentResolver().query(Media.EXTERNAL_CONTENT_URI, new String[]{"_id", "_data", "bucket_display_name", "date_added"}, "_data like '%" + this.mFolder + "%'", null, "date_added desc");
        int column_index_data = cursor.getColumnIndexOrThrow("_data");
        int column_index_folder_name = cursor.getColumnIndex("bucket_display_name");
        while (cursor.moveToNext()) {
            PickerImageModel vo = new PickerImageModel();
            vo.imgID = cursor.getInt(cursor.getColumnIndexOrThrow("_id"));
            vo.ImagePathFolder = cursor.getString(column_index_folder_name);
            vo.ImagePath = cursor.getString(column_index_data);
            if (this.mSelectedModels != null && this.mSelectedModels.size() > 0) {
                vo.isSelected = isSelected(vo.imgID).booleanValue();
                if (vo.isSelected) {
                    this.mSelectedModels.add(vo);
                }
            }
            listOfAllImages.add(vo);
        }
        if (!this.mAllRegedImgsState.booleanValue()) {
            this.mSelectedImgCnt = 0;
        }
        return listOfAllImages;
    }

    /* access modifiers changed from: private */
    public void onSelectedImgIdx(int selectedCnt) {
        if (this.mListOfAllImages != null && this.mListOfAllImages.size() > 0) {
            ((TextView) findViewById(R.id.countLabel)).setText(selectedCnt + "/" + this.mListOfAllImages.size());
        }
        findViewById(R.id.review_gallery_save).setEnabled(this.mSelectedImgCnt >= 1);
    }

    private Boolean isSelected(int imgID) {
        Boolean isselected = Boolean.valueOf(false);
        PickerImageModel removeVo = null;
        Iterator<PickerImageModel> it = this.mSelectedModels.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            PickerImageModel regImgid = it.next();
            if (regImgid.getImgID() == imgID) {
                removeVo = regImgid;
                isselected = Boolean.valueOf(true);
                this.mAllRegedImgsState = Boolean.valueOf(true);
                this.mSelectedImgCnt++;
                this.mAllRegSelectedImgCnt++;
                break;
            }
        }
        if (isselected.booleanValue()) {
            this.mSelectedModels.remove(removeVo);
        }
        return isselected;
    }
}