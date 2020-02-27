package com.ning.http.client.filter;

public interface ResponseFilter {
    FilterContext filter(FilterContext filterContext) throws FilterException;
}