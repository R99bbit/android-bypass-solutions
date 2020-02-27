package com.igaworks.interfaces;

public interface IgawRewardItemEventListener {
    void onDidGiveRewardItemResult(boolean z, String str, int i, String str2);

    void onGetRewardInfo(boolean z, String str, IgawRewardItem[] igawRewardItemArr);
}