package com.reconlens.model;

/**
 * Mirrors {@code burp.api.montoya.http.message.params.HttpParameterType}, kept
 * as our own enum so every class under {@code com.reconlens.analysis} can be
 * compiled and unit-tested with plain {@code javac} -- no Burp, no Montoya API
 * jar, no Burp Suite installation required.
 */
public enum ParamType {
    URL, BODY, COOKIE, JSON, XML, XML_ATTRIBUTE, MULTIPART_ATTRIBUTE, UNKNOWN
}
