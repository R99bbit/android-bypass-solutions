package com.igaworks.adbrix.cpe.activitydialog;

import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import com.igaworks.adbrix.cpe.common.IconPagerAdapter;
import java.util.List;

public class PlaceSlidesFragmentAdapter extends FragmentPagerAdapter implements IconPagerAdapter {
    private int campaignKey;
    private List<String> imgUrls;
    private boolean isFullScreen = false;
    private int mCount;

    public PlaceSlidesFragmentAdapter(FragmentManager fm, List<String> imgUrls2, int campaignKey2, boolean isFullScreen2) {
        super(fm);
        this.mCount = imgUrls2.size();
        this.imgUrls = imgUrls2;
        this.campaignKey = campaignKey2;
        this.isFullScreen = isFullScreen2;
    }

    public Fragment getItem(int position) {
        return PlaceSlideFragment.newInstance(this.imgUrls.get(position), this.campaignKey, position, this.isFullScreen);
    }

    public int getCount() {
        return this.mCount;
    }

    public void setCount(int count) {
        if (count > 0 && count <= 10) {
            this.mCount = count;
            notifyDataSetChanged();
        }
    }
}