package com.ning.http.client.filter;

public interface RequestFilter {
    FilterContext filter(FilterContext filterContext) throws FilterException;
}