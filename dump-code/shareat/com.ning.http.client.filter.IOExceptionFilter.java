package com.ning.http.client.filter;

public interface IOExceptionFilter {
    FilterContext filter(FilterContext filterContext) throws FilterException;
}