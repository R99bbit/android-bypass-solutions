package com.nuvent.shareat.adapter.friend;

import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import com.nuvent.shareat.fragment.FriendFragment;

public class FriendAdapter extends FragmentStatePagerAdapter {
    private static final int MENU_COUNT = 3;

    public FriendAdapter(FragmentManager fm) {
        super(fm);
    }

    public Fragment getItem(int position) {
        switch (position) {
            case 0:
                FriendFragment friendFragment = new FriendFragment();
                friendFragment.setType(1);
                return friendFragment;
            case 1:
                FriendFragment followFragment = new FriendFragment();
                followFragment.setType(2);
                return followFragment;
            default:
                FriendFragment folloingFragment = new FriendFragment();
                folloingFragment.setType(3);
                return folloingFragment;
        }
    }

    public int getCount() {
        return 3;
    }
}