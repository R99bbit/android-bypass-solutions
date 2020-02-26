package com.embrain.panelpower.networks.vo;

import java.util.ArrayList;

public class ResponseSurveyExpress {
    public String result;
    public ArrayList<SurveyResponseVO> surveyexpress;

    public class SurveyResponseVO {
        public int firstCnt;
        public int lastCnt;
        public int puIdx;
        public String surveyexpress = "";
        public int totCnt;

        public SurveyResponseVO() {
        }
    }

    public boolean isSuccess() {
        return "success".equals(this.result);
    }

    public ArrayList<SurveyResponseVO> getSurveyexpress() {
        if (isSuccess()) {
            return this.surveyexpress;
        }
        return null;
    }
}