package com.nuvent.shareat.model;

import java.io.Serializable;

public class BaseResultModel implements Serializable {
    public String result;
    public String result_code;

    public boolean isSuccess() {
        return this.result != null && this.result.equals("Y");
    }

    public boolean isOkResponse() {
        return this.result_code != null && this.result_code.equals("200");
    }

    public String getErrorMessage() {
        if (this.result_code == null) {
            return "Null Error";
        }
        if (this.result_code.equals("100")) {
            return "Param Error";
        }
        if (this.result_code.equals("400")) {
            return "Bad Request";
        }
        if (this.result_code.equals("500")) {
            return "Internal Server Error";
        }
        if (this.result_code.equals("200")) {
            return "OK";
        }
        return "Unknown Error";
    }

    public String getResult_code() {
        return this.result_code;
    }

    public void setResult_code(String result_code2) {
        this.result_code = result_code2;
    }

    public String getResult() {
        return this.result;
    }

    public void setResult(String result2) {
        this.result = result2;
    }
}