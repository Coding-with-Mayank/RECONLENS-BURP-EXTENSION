package com.reconlens.model;

/** A single request parameter, stripped down to just what the analysis package needs. */
public final class HttpParam {
    public final String name;
    public final String value;
    public final ParamType type;

    public HttpParam(String name, String value, ParamType type) {
        this.name = name == null ? "" : name;
        this.value = value == null ? "" : value;
        this.type = type == null ? ParamType.UNKNOWN : type;
    }

    @Override
    public String toString() {
        return name + "=" + value + " (" + type + ")";
    }
}
