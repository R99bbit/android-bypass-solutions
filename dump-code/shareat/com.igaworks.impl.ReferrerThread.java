package com.igaworks.impl;

import android.content.Context;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.dao.AppImpressionDAO;
import com.igaworks.dao.ReferralInfoDAO;

public class ReferrerThread extends Thread {
    private static int MAXIMUM_RETRY = 10;
    private Context context;
    private volatile boolean stop = false;

    public void run() {
        Log.i(IgawConstant.QA_TAG, "ReferrerThread has started ");
        this.context = CommonFrameworkImpl.getContext().getApplicationContext();
        int retry = 0;
        while (!this.stop) {
            try {
                if (ReferralInfoDAO.getOnReceiveReferralFlag(this.context) || CommonFrameworkImpl.parameter.getReferralKey() == -1 || CommonFrameworkImpl.parameter.getADBrixUserNo() < 1 || !AppImpressionDAO.getSynAdbrix(this.context)) {
                    InternalAction.getInstance().referrerCallForAdbrix(this.context, CommonFrameworkImpl.isTest, CommonFrameworkImpl.parameter, CommonFrameworkImpl.httpManager);
                    Thread.sleep(30000);
                    retry++;
                    if (retry > MAXIMUM_RETRY) {
                        requestStop();
                    }
                } else {
                    requestStop();
                }
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "ReferrerThread Error: " + e.getMessage());
                requestStop();
            }
        }
        if (this.stop) {
            Log.i(IgawConstant.QA_TAG, "ReferrerThread stopped");
        }
    }

    public void requestStop() {
        this.stop = true;
    }
}