package com.xxl.job.admin.service;

import com.xxl.job.admin.core.model.XxlJobUser;
import com.xxl.job.admin.core.util.CookieUtil;
import com.xxl.job.admin.core.util.I18nUtil;
import com.xxl.job.admin.core.util.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import com.xxl.job.admin.dao.XxlJobUserDao;
import com.xxl.job.core.biz.model.ReturnT;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.DigestUtils;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.math.BigInteger;

/**
 * @author xuxueli 2019-05-04 22:13:264
 */
@Configuration
public class LoginService {

	public static final String LOGIN_IDENTITY_KEY = "XXL_JOB_LOGIN_IDENTITY";

	private static final Logger logger = LoggerFactory.getLogger(LoginService.class);

	@Value("${xxl.job.login.allowedIps:}")
	private String allowedIps;

	@Value("${xxl.job.login.allowedDomains:}")
	private String allowedDomains;

	@Resource
	private XxlJobUserDao xxlJobUserDao;


	private String makeToken(XxlJobUser xxlJobUser){
		String tokenJson = JacksonUtil.writeValueAsString(xxlJobUser);
		String tokenHex = new BigInteger(tokenJson.getBytes()).toString(16);
		return tokenHex;
	}
	private XxlJobUser parseToken(String tokenHex){
		XxlJobUser xxlJobUser = null;
		if (tokenHex != null) {
			String tokenJson = new String(new BigInteger(tokenHex, 16).toByteArray());      // username_password(md5)
			xxlJobUser = JacksonUtil.readValue(tokenJson, XxlJobUser.class);
		}
		return xxlJobUser;
	}


	public ReturnT<String> login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean ifRemember){

		// param
		if (username==null || username.trim().length()==0 || password==null || password.trim().length()==0){
			logger.warn("Login param empty from IP {}", getClientIp(request));
			return new ReturnT<String>(500, I18nUtil.getString("login_param_empty"));
		}

		String clientIp = getClientIp(request);
		String domain = request.getServerName();

		// ip limit
		if (allowedIps != null && allowedIps.trim().length() > 0) {
			Set<String> ipSet = Arrays.stream(allowedIps.split(",")).map(String::trim).filter(s -> s.length() > 0).collect(Collectors.toSet());
			if (!ipSet.contains(clientIp)) {
				logger.warn("Login IP forbidden for user {} from IP {}", username, clientIp);
				return new ReturnT<String>(500, I18nUtil.getString("login_ip_forbidden"));
			}
		}

		// domain limit
		if (allowedDomains != null && allowedDomains.trim().length() > 0) {
			Set<String> domainSet = Arrays.stream(allowedDomains.split(",")).map(String::trim).filter(s -> s.length() > 0).collect(Collectors.toSet());
			if (!domainSet.contains(domain)) {
				logger.warn("Login domain forbidden for user {} from domain {}", username, domain);
				return new ReturnT<String>(500, I18nUtil.getString("login_domain_forbidden"));
			}
		}

		// valid passowrd
		XxlJobUser xxlJobUser = xxlJobUserDao.loadByUserName(username);
		if (xxlJobUser == null) {
			logger.warn("Login failed, user not found: {} from IP {}", username, clientIp);
			return new ReturnT<String>(500, I18nUtil.getString("login_param_unvalid"));
		}
		String passwordMd5 = DigestUtils.md5DigestAsHex(password.getBytes());
		if (!passwordMd5.equals(xxlJobUser.getPassword())) {
			logger.warn("Login failed, password error for user {} from IP {}", username, clientIp);
			return new ReturnT<String>(500, I18nUtil.getString("login_param_unvalid"));
		}

		String loginToken = makeToken(xxlJobUser);

		// do login
		CookieUtil.set(response, LOGIN_IDENTITY_KEY, loginToken, ifRemember);
		logger.info("User {} login success from IP {} domain {}", username, clientIp, domain);
		return ReturnT.SUCCESS;
	}

	/**
	 * logout
	 *
	 * @param request
	 * @param response
	 */
	public ReturnT<String> logout(HttpServletRequest request, HttpServletResponse response){
		CookieUtil.remove(request, response, LOGIN_IDENTITY_KEY);
		return ReturnT.SUCCESS;
	}

	/**
	 * logout
	 *
	 * @param request
	 * @return
	 */
	public XxlJobUser ifLogin(HttpServletRequest request, HttpServletResponse response){
		String cookieToken = CookieUtil.getValue(request, LOGIN_IDENTITY_KEY);
		if (cookieToken != null) {
			XxlJobUser cookieUser = null;
			try {
				cookieUser = parseToken(cookieToken);
			} catch (Exception e) {
				logout(request, response);
			}
			if (cookieUser != null) {
				XxlJobUser dbUser = xxlJobUserDao.loadByUserName(cookieUser.getUsername());
				if (dbUser != null) {
					if (cookieUser.getPassword().equals(dbUser.getPassword())) {
						return dbUser;
					}
				}
			}
		}
		return null;
	}

	private String getClientIp(HttpServletRequest request) {
		String[] headers = {"X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
		for (String header : headers) {
			String ip = request.getHeader(header);
			if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
				int index = ip.indexOf(',');
				if (index != -1) {
					ip = ip.substring(0, index);
				}
				return ip.trim();
			}
		}
		return request.getRemoteAddr();
	}


}
