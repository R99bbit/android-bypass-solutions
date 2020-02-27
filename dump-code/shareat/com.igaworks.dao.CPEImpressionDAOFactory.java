package com.igaworks.dao;

public class CPEImpressionDAOFactory {
    public static AbstractCPEImpressionDAO getImpressionDAO(String scheme, String key, int scheduleType) {
        if (!scheme.equals("impression")) {
            return null;
        }
        if (key.equals("session_count")) {
            return CPESessionImpressionDAO.getInstance();
        }
        return CPEPersistImpressionDAO.getInstance();
    }
}