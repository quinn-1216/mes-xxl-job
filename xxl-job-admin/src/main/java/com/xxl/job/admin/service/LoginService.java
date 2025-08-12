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

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

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

	@Value("${xxl.job.login.ldapUrl:}")
	private String ldapUrl;

	@Value("${xxl.job.login.ldapDnPattern:}")
	private String ldapDnPattern;

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

		// valid password via LDAP or local
		XxlJobUser xxlJobUser = xxlJobUserDao.loadByUserName(username);
		if (xxlJobUser == null) {
			logger.warn("Login failed, user not found: {} from IP {}", username, clientIp);
			return new ReturnT<String>(500, I18nUtil.getString("login_param_unvalid"));
		}
		if (ldapUrl != null && ldapUrl.trim().length() > 0 && ldapDnPattern != null && ldapDnPattern.trim().length() > 0) {
			if (!ldapAuthenticate(username, password)) {
				logger.warn("Login failed, LDAP auth failed for user {} from IP {}", username, clientIp);
				return new ReturnT<String>(500, I18nUtil.getString("login_ldap_fail"));
			}
		} else {
			String passwordMd5 = DigestUtils.md5DigestAsHex(password.getBytes());
			if (!passwordMd5.equals(xxlJobUser.getPassword())) {
				logger.warn("Login failed, password error for user {} from IP {}", username, clientIp);
				return new ReturnT<String>(500, I18nUtil.getString("login_param_unvalid"));
			}
		}

		String loginToken = makeToken(xxlJobUser);

		// do login
		CookieUtil.set(response, LOGIN_IDENTITY_KEY, loginToken, ifRemember);
		logger.info("User {} login success from IP {}", username, clientIp);
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
	private boolean ldapAuthenticate(String username, String password) {
		String userDn = ldapDnPattern.replace("{0}", username);
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapUrl);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, userDn);
		env.put(Context.SECURITY_CREDENTIALS, password);
		try {
			new InitialDirContext(env).close();
			return true;
		} catch (NamingException e) {
			logger.warn("LDAP authenticate exception for user {}", username, e);
			return false;
		}
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
