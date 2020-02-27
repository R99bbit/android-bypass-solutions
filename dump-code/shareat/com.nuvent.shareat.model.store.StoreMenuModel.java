package com.nuvent.shareat.model.store;

import java.util.Locale;

public class StoreMenuModel {
    public String menu_change;
    public String menu_name;
    public String menu_price;
    public String menu_rank;
    public int rank_percent;

    public void setRank_percent(int rank_percent2) {
        this.rank_percent = rank_percent2;
    }

    public void setMenu_price(String menu_price2) {
        this.menu_price = menu_price2;
    }

    public void setMenu_rank(String menu_rank2) {
        this.menu_rank = menu_rank2;
    }

    public void setMenu_change(String menu_change2) {
        this.menu_change = menu_change2;
    }

    public void setMenu_name(String menu_name2) {
        this.menu_name = menu_name2;
    }

    public String getPrice() {
        try {
            return String.format(Locale.getDefault(), "%,d", new Object[]{Integer.valueOf(this.menu_price)});
        } catch (NumberFormatException e) {
            return this.menu_price;
        }
    }

    public int getRank_percent() {
        return this.rank_percent;
    }

    public String getMenu_price() {
        return this.menu_price;
    }

    public String getMenu_name() {
        return this.menu_name;
    }

    public String getMenu_rank() {
        return this.menu_rank;
    }

    public String getMenu_change() {
        return this.menu_change;
    }
}