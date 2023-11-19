package com.coderscampus.SpringSecurityJWTDemo.utils;

import jakarta.servlet.http.Cookie;

public class CookieUtils {
	public static Cookie createAccessTokenCookie(String value) {
		Cookie accessTokenCookie = new Cookie("accessToken", value);
		return accessTokenCookie;
	}

	public static Cookie createRefeshTokenCookie(String value) {
		
		Cookie accessRefreshCookie = new Cookie("refreshToken", value);
		return accessRefreshCookie;
	}

}