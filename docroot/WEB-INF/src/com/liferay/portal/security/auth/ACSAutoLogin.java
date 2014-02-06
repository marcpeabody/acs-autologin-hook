package com.liferay.portal.security.auth;

import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.Role;
import com.liferay.portal.model.User;
import com.liferay.portal.service.RoleLocalServiceUtil;
import com.liferay.portal.service.ServiceContext;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;

import java.util.Calendar;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.microsoftopentechnologies.acs.federation.ACSConfigurationHelper;
import com.microsoftopentechnologies.acs.federation.ACSFederationAuthFilter;
import com.microsoftopentechnologies.acs.saml.SAMLAssertion;
import com.microsoftopentechnologies.acs.serialize.AssertionCookieSerializer;

public class ACSAutoLogin implements AutoLogin {
	private static Log _log = LogFactoryUtil.getLog(ACSAutoLogin.class);

	@Override
	public String[] login(HttpServletRequest req, HttpServletResponse res)
			throws AutoLoginException {

		String[] credentials = null;

		try {
			ACSConfigurationHelper config = ACSFederationAuthFilter.configuration;
			AssertionCookieSerializer acs = ((AssertionCookieSerializer) config
					.getAssertionSerializer());
			SAMLAssertion assertion = acs.getAssertion(req);
			String subdomain = getAssertionValue(assertion, "subdomain");
			String emailaddress = getAssertionValue(assertion, "emailaddress");
			String givenname = getAssertionValue(assertion, "givenname");
			String surname = getAssertionValue(assertion, "surname");
			String screenName = getAssertionValue(assertion, "name") + "-" + subdomain;
			String roleName = getAssertionValue(assertion, "Group");

		    credentials = loginFake(req, screenName, emailaddress, givenname, surname, roleName);
		    return credentials;

		} catch (Exception e) {
			logError(e);
			throw new AutoLoginException(e);
		}
	}

	/**
	 * Create new user with passed in parameters. Will fail if any
	 * parameters are not invalid or if role with name does not exist.
	 * 
	 * @param companyId
	 * @param screenName
	 * @param emailAddress
	 * @param firstName
	 * @param lastName
	 * @param roleName
	 * @return
	 * @throws Exception
	 */
	private User addUser(long companyId, String screenName,
			String emailAddress, String firstName, String lastName, String roleName)
			throws Exception {

		long creatorUserId = 0;
		boolean autoPassword = true;
		String password1 = null;
		String password2 = null;
		boolean autoScreenName = false;
		long facebookId = 0;
		String openId = StringPool.BLANK;
		Locale locale = Locale.US;
		String middleName = StringPool.BLANK;
		int prefixId = 0;
		int suffixId = 0;
		boolean male = true;
		int birthdayMonth = Calendar.JANUARY;
		int birthdayDay = 1;
		int birthdayYear = 1970;
		String jobTitle = StringPool.BLANK;

		long[] groupIds = null;
		long[] organizationIds = null;
		long[] roleIds = null;
		long[] userGroupIds = null;

		boolean sendEmail = false;
		ServiceContext serviceContext = null;
		
		Role role = RoleLocalServiceUtil.getRole(companyId, roleName);
		
		User user = UserLocalServiceUtil.addUser(creatorUserId, companyId,
				autoPassword, password1, password2, autoScreenName, screenName,
				emailAddress, facebookId, openId, locale, firstName,
				middleName, lastName, prefixId, suffixId, male, birthdayMonth,
				birthdayDay, birthdayYear, jobTitle, groupIds, organizationIds,
				roleIds, userGroupIds, sendEmail, serviceContext);
		user.setPasswordReset(false);
		user.setReminderQueryQuestion("what-is-your-library-card-number");
		user.setReminderQueryAnswer("927383900287237");
		
		RoleLocalServiceUtil.addUserRole(user.getUserId(), role.getRoleId());
		UserLocalServiceUtil.updateUser(user);
		return user;
	}

	private void logError(Exception e) {
		_log.error("Exception message = " + e.getMessage() + " cause = "
				+ e.getCause());
		if (_log.isDebugEnabled()) {
			_log.error(e);
		}
	}

	@Override
	public String[] handleException(HttpServletRequest request,
			HttpServletResponse response, Exception e)
			throws AutoLoginException {
		// taken from BaseAutoLogin
		if (Validator.isNull(request
				.getAttribute(AutoLogin.AUTO_LOGIN_REDIRECT))) {
			throw new AutoLoginException(e);
		}
		_log.error(e, e);
		return null;
	}

	public String[] loginFake(HttpServletRequest request, String screenName,
			String emailAddress, String firstName, String lastName, String roleName) throws Exception {
		String[] credentials = null;

		try {
			long companyId = PortalUtil.getCompanyId(request);

			if (Validator.isNull(screenName)) {
				return credentials;
			}

			User user = null;

			try {
				user = UserLocalServiceUtil.getUserByScreenName(companyId,
						screenName);
			} catch (NoSuchUserException nsue) {
				user = addUser(companyId, screenName, emailAddress, firstName,
						lastName, roleName);
			}
			credentials = credentialsForUser(user);
			return credentials;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return credentials;
	}

	private String getAssertionValue(SAMLAssertion assertion,
			String attributeName) {
		SAMLAssertion.Attribute[] attributes = assertion.getAttributes();
		for (SAMLAssertion.Attribute attribute : attributes) {
			if (attribute.getName().endsWith("/claims/" + attributeName)) {
				String[] values = attribute.getValues();
				if (values != null && values.length > 0) {
					return stripDomainFromUserName(values[0]);
				}
			}
		}
		return "";
	}
	
	private static String stripDomainFromUserName(String name) {
        String[] sections = name.split("\\\\");
        return sections[sections.length - 1];
	}
	
	private String[] credentialsForUser(User user) {
		String[] credentials = new String[3];
	    credentials[0] = String.valueOf(user.getUserId());
		credentials[1] = user.getPassword();
		credentials[2] = Boolean.TRUE.toString();
		return credentials;
	}
}