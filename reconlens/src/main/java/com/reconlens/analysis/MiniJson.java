package com.reconlens.analysis;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, dependency-free JSON parser. Only used internally for two narrow
 * jobs: comparing the *shape* of response bodies across near-duplicate
 * requests ({@link ResponseDiffAnalyzer}), and decoding JWT header/payload
 * segments ({@link JwtInspector}). It is deliberately not a general-purpose
 * JSON library -- no custom serialization, no streaming, no schema validation,
 * just enough to turn a JSON string into java.util.Map/List/String/Number/
 * Boolean/null. Keeping this in-house avoids pulling a real JSON library (and
 * the Maven-shade relocation that comes with it) into the extension jar for
 * two narrow call sites.
 */
final class MiniJson {

    private final String src;
    private int pos;

    private MiniJson(String src) {
        this.src = src;
    }

    /** Returns null instead of throwing on anything that doesn't look like valid JSON. */
    static Object parseQuietly(String text) {
        if (text == null) return null;
        try {
            MiniJson p = new MiniJson(text);
            p.skipWs();
            Object v = p.parseValue();
            return v;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Base64url-decodes a JWT segment and parses it as JSON, or returns null on any failure. */
    static Object parseBase64UrlJson(String segment) {
        try {
            String padded = padBase64(segment);
            byte[] bytes = java.util.Base64.getUrlDecoder().decode(padded);
            return parseQuietly(new String(bytes, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String padBase64(String base64url) {
        int rem = base64url.length() % 4;
        if (rem == 0) return base64url;
        StringBuilder sb = new StringBuilder(base64url);
        for (int i = 0; i < (4 - rem); i++) sb.append('=');
        return sb.toString();
    }

    private Object parseValue() {
        char c = peek();
        switch (c) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': return parseString();
            case 't': expect("true"); return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null"); return null;
            default: return parseNumber();
        }
    }

    private Map<String, Object> parseObject() {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++; // consume '{'
        skipWs();
        if (peek() == '}') { pos++; return map; }
        while (true) {
            skipWs();
            String key = parseString();
            skipWs();
            if (peek() != ':') throw new IllegalStateException("expected ':' in object");
            pos++;
            skipWs();
            map.put(key, parseValue());
            skipWs();
            char c = peek();
            if (c == ',') { pos++; continue; }
            if (c == '}') { pos++; break; }
            throw new IllegalStateException("expected ',' or '}' in object");
        }
        return map;
    }

    private List<Object> parseArray() {
        List<Object> list = new ArrayList<>();
        pos++; // consume '['
        skipWs();
        if (peek() == ']') { pos++; return list; }
        while (true) {
            skipWs();
            list.add(parseValue());
            skipWs();
            char c = peek();
            if (c == ',') { pos++; continue; }
            if (c == ']') { pos++; break; }
            throw new IllegalStateException("expected ',' or ']' in array");
        }
        return list;
    }

    private String parseString() {
        if (peek() != '"') throw new IllegalStateException("expected opening '\"'");
        pos++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = src.charAt(pos++);
            if (c == '"') break;
            if (c == '\\') {
                char n = src.charAt(pos++);
                switch (n) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'u':
                        String hex = src.substring(pos, pos + 4);
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                        break;
                    default: sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private Object parseNumber() {
        int start = pos;
        if (peek() == '-') pos++;
        while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        boolean isDouble = false;
        if (pos < src.length() && src.charAt(pos) == '.') {
            isDouble = true;
            pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        }
        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            isDouble = true;
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        }
        String num = src.substring(start, pos);
        if (num.isEmpty() || num.equals("-")) throw new IllegalStateException("invalid number literal");
        return isDouble ? (Object) Double.parseDouble(num) : (Object) Long.parseLong(num);
    }

    private void expect(String literal) {
        if (pos + literal.length() > src.length() || !src.regionMatches(pos, literal, 0, literal.length())) {
            throw new IllegalStateException("expected literal " + literal);
        }
        pos += literal.length();
    }

    private char peek() {
        if (pos >= src.length()) throw new IllegalStateException("unexpected end of input");
        return src.charAt(pos);
    }

    private void skipWs() {
        while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
    }
}
