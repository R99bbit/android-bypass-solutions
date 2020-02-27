package com.nuvent.shareat.model;

public class SocketInfoModel extends BaseResultModel {
    private String host;
    private String port;
    private String protocol;

    public String getProtocol() {
        return this.protocol;
    }

    public String getHost() {
        return this.host;
    }

    public String getPort() {
        return this.port;
    }
}