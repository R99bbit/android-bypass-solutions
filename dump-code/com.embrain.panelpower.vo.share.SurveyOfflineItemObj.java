package com.embrain.panelpower.vo.share;

import com.embrain.panelbigdata.utils.StringUtils;
import java.io.Serializable;
import java.util.ArrayList;

public class SurveyOfflineItemObj extends SurveyItemObj implements Serializable {
    public String allowReqYn;
    public String cont;
    public String creDt;
    public ArrayList<SurveyGroupItemVO> grpList;
    public String grpMultiYn;
    public String grpUseYn;
    public String invPayTpCd;
    public String isRequestedYn;
    public String location;
    public String maxInvPayVal;
    public String maxResPayVal;
    public String mgrCellNo;
    public String mgrEmail;
    public String mgrNm;
    public String minInvPayVal;
    public String minResPayVal;
    public String payType;
    public ArrayList<SurveyQuestionItemVO> qestnList;
    public String qestnUseYn;
    public String regEndDt;
    public String regStaDt;
    public String reqDt;
    public String reqreTime;
    public String resPayTpCd;
    public String srvInvCnt;
    public String srvNo;
    public String srvStatCd;
    public String statusCd;
    public String tgtDesc;

    public String getSurveyPoint() {
        if (this.resPayTpCd.equals("E")) {
            StringBuilder sb = new StringBuilder();
            sb.append(StringUtils.getCommaValue(this.minResPayVal));
            sb.append("\uc6d0");
            return sb.toString();
        }
        if (this.resPayTpCd.equals("D")) {
            if (!StringUtils.isEmpty(this.minResPayVal) && !StringUtils.isEmpty(this.maxResPayVal)) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append(StringUtils.getCommaValue(this.minResPayVal));
                sb2.append("\uc6d0 ~ ");
                sb2.append(StringUtils.getCommaValue(this.maxResPayVal));
                sb2.append("\uc6d0 (\ucc28\ub4f1)");
                return sb2.toString();
            } else if (StringUtils.isEmpty(this.minResPayVal)) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append("~ ");
                sb3.append(StringUtils.getCommaValue(this.maxResPayVal));
                sb3.append("\uc6d0 (\ucc28\ub4f1)");
                return sb3.toString();
            } else if (StringUtils.isEmpty(this.maxResPayVal)) {
                StringBuilder sb4 = new StringBuilder();
                sb4.append(StringUtils.getCommaValue(this.minResPayVal));
                sb4.append("\uc6d0 ~ (\ucc28\ub4f1)");
                return sb4.toString();
            }
        }
        return "-";
    }

    public String getInvitePoint() {
        if (this.invPayTpCd.equals("N")) {
            return " -";
        }
        if (this.invPayTpCd.equals("E")) {
            StringBuilder sb = new StringBuilder();
            sb.append(StringUtils.getCommaValue(this.minInvPayVal));
            sb.append("\uc6d0");
            return sb.toString();
        }
        if (this.invPayTpCd.equals("D")) {
            if (!StringUtils.isEmpty(this.minInvPayVal) && !StringUtils.isEmpty(this.maxInvPayVal)) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append(StringUtils.getCommaValue(this.minInvPayVal));
                sb2.append("\uc6d0 ~ ");
                sb2.append(StringUtils.getCommaValue(this.maxInvPayVal));
                sb2.append("\uc6d0 (\ucc28\ub4f1)");
                return sb2.toString();
            } else if (StringUtils.isEmpty(this.minInvPayVal)) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append("~ ");
                sb3.append(StringUtils.getCommaValue(this.maxInvPayVal));
                sb3.append("\uc6d0 (\ucc28\ub4f1)");
                return sb3.toString();
            } else if (StringUtils.isEmpty(this.maxInvPayVal)) {
                StringBuilder sb4 = new StringBuilder();
                sb4.append(StringUtils.getCommaValue(this.minInvPayVal));
                sb4.append("\uc6d0 ~ (\ucc28\ub4f1)");
                return sb4.toString();
            }
        }
        return " -";
    }

    public String getRegDate() {
        if (StringUtils.getYYYY_MM_DD(this.regStaDt).equals(StringUtils.getYYYY_MM_DD(this.regEndDt))) {
            return StringUtils.getYYYY_MM_DD(this.regStaDt);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.getYYYY_MM_DD(this.regStaDt));
        sb.append("~");
        sb.append(StringUtils.getYYYY_MM_DD(this.regEndDt));
        return sb.toString();
    }

    public String getSrvDate() {
        if (StringUtils.getYYYY_MM_DD(this.srvStaDt).equals(StringUtils.getYYYY_MM_DD(this.srvEndDt))) {
            return StringUtils.getYYYY_MM_DD(this.srvStaDt);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.getYYYY_MM_DD(this.srvStaDt));
        sb.append("~");
        sb.append(StringUtils.getYYYY_MM_DD(this.srvEndDt));
        return sb.toString();
    }

    public String getReqDt() {
        String str = this.reqDt;
        if (str == null) {
            return "\uc5c6\uc74c";
        }
        return StringUtils.getYYYY_MM_DD(str);
    }

    public String getManagerInfor() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.mgrNm);
        sb.append(" / ");
        sb.append(this.mgrEmail);
        if (this.mgrCellNo != null) {
            sb.append(" / ");
            sb.append(this.mgrCellNo);
        }
        return sb.toString();
    }

    public boolean isRequest() {
        return StringUtils.isYn(this.allowReqYn);
    }

    public boolean isRequested() {
        return StringUtils.isYn(this.isRequestedYn);
    }

    public boolean isInvite() {
        String str = this.invPayTpCd;
        if (str == null) {
            return false;
        }
        return !str.equals("N");
    }
}