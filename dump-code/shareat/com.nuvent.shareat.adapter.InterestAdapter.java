package com.nuvent.shareat.adapter;

import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import com.nuvent.shareat.fragment.profile.PhotoFragment;
import com.nuvent.shareat.fragment.profile.ReviewFragment;
import com.nuvent.shareat.fragment.profile.VisitFragment;
import com.nuvent.shareat.fragment.profile.ZzimFragment;

public class InterestAdapter extends FragmentStatePagerAdapter {
    private static final int MENU_COUNT = 4;
    private String mTargetUserSno = null;

    public InterestAdapter(FragmentManager fm) {
        super(fm);
    }

    public Fragment getItem(int position) {
        switch (position) {
            case 0:
                VisitFragment visitFragment = new VisitFragment();
                visitFragment.setTargetUserSno(this.mTargetUserSno);
                return visitFragment;
            case 1:
                PhotoFragment photoFragment = new PhotoFragment();
                photoFragment.setTargetUserSno(this.mTargetUserSno);
                return photoFragment;
            case 2:
                ReviewFragment reviewFragment = new ReviewFragment();
                reviewFragment.setTargetUserSno(this.mTargetUserSno);
                return reviewFragment;
            default:
                ZzimFragment zzimFragment = new ZzimFragment();
                zzimFragment.setTargetUserSno(this.mTargetUserSno);
                return zzimFragment;
        }
    }

    public void setTargetUserSno(String targetUserSno) {
        this.mTargetUserSno = targetUserSno;
        notifyDataSetChanged();
    }

    public int getCount() {
        return 4;
    }
}