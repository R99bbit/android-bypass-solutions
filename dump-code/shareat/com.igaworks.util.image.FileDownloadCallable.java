package com.igaworks.util.image;

import java.io.File;
import java.util.concurrent.Callable;

public class FileDownloadCallable implements Callable<File> {
    private File file;
    private String url;

    public FileDownloadCallable(String url2, File file2) {
        this.url = url2;
        this.file = file2;
    }

    public File call() throws Exception {
        return HttpRequestHelper.getInstance().download(this.url, this.file);
    }
}