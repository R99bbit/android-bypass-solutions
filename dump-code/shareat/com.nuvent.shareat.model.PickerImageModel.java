package com.nuvent.shareat.model;

import java.io.Serializable;

public class PickerImageModel implements Serializable {
    public String ImagePath;
    public String ImagePathFolder;
    public int imgID;
    public boolean isSelected = false;

    public void setIsSelected(boolean isSelected2) {
        this.isSelected = isSelected2;
    }

    public void setImagePathFolder(String imagePathFolder) {
        this.ImagePathFolder = imagePathFolder;
    }

    public void setImagePath(String imagePath) {
        this.ImagePath = imagePath;
    }

    public void setImgID(int imgID2) {
        this.imgID = imgID2;
    }

    public String getImagePath() {
        return this.ImagePath;
    }

    public String getImagePathFolder() {
        return this.ImagePathFolder;
    }

    public int getImgID() {
        return this.imgID;
    }

    public boolean isSelected() {
        return this.isSelected;
    }
}