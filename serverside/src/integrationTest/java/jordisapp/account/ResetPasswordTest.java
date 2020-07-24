/*
 * @bot-written
 * 
 * WARNING AND NOTICE
 * Any access, download, storage, and/or use of this source code is subject to the terms and conditions of the
 * Full Software Licence as accepted by you before being granted access to this source code and other materials,
 * the terms of which can be accessed on the Codebots website at https://codebots.com/full-software-licence. Any
 * commercial use in contravention of the terms of the Full Software Licence may be pursued by Codebots through
 * licence termination and further legal action, and be required to indemnify Codebots for any loss or damage,
 * including interest and costs. You are deemed to have accepted the terms of the Full Software Licence on any
 * access, download, storage, and/or use of this source code.
 * 
 * BOT WARNING
 * This file is bot-written.
 * Any changes out side of "protected regions" will be lost next time the bot makes any changes.
 */
package jordisapp.account;


import jordisapp.SpringTestConfiguration;
import jordisapp.utils.*;
import jordisapp.configs.security.helpers.AnonymousHelper;
import jordisapp.entities.*;
import jordisapp.lib.token.models.TokenEntity;
import jordisapp.lib.token.services.TokenService;
import jordisapp.services.*;
import jordisapp.configs.security.services.AuthenticationService;
import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.*;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.icegreen.greenmail.util.GreenMailUtil;
import javax.mail.internet.MimeMessage;
import javax.mail.MessagingException;
import java.util.*;
import java.time.OffsetDateTime;
import java.util.stream.Collectors;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

// % protected region % [Add any additional imports here] off begin
// % protected region % [Add any additional imports here] end

/**
 * Integrated test for the whole reset password functionality
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = SpringTestConfiguration.class)
@ActiveProfiles("test")
public class ResetPasswordTest {

	@Autowired
	private WebApplicationContext context;
	
	@Autowired
	private TokenService tokenService;

	@Autowired
	private AuthenticationService authenticationService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Rule
	public SmtpServerRule smtpServerRule = new SmtpServerRule();

	@Value("${clientside.hostname}")
	private String clientsideHost;

	private final String resetPasswordEndpoint = "/api/authorization/reset-password";
	private final String requestResetPasswordEndpoint = "/api/authorization/request-reset-password";

	private MockMvc mvc;

	// % protected region % [Add any additional fields here] off begin
	// % protected region % [Add any additional fields here] end

	@Before
	public void setup() {
		// % protected region % [Add any additional logic for setup before the main body here] off begin
		// % protected region % [Add any additional logic for setup before the main body here] end

		mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.apply(springSecurity())
				.build();

		// % protected region % [Add any additional logic for setup after the main body here] off begin
		// % protected region % [Add any additional logic for setup after the main body here] end
	}


	@Test
	public void requestToResetPassword_withInValidUsername() throws Exception{

		Map<String, Object> body = new HashMap<>();

		body.put("username", "not_exist@example.com");
		// % protected region % [Add any additional request parameters in requestToResetPassword_withInValidUsername here] off begin
		// % protected region % [Add any additional request parameters in requestToResetPassword_withInValidUsername here] end

		ResultActions result = RequestUtil.sendRequestByEndpointWithJsonBody(mvc, requestResetPasswordEndpoint, body);

		// % protected region % [Add any additional logic after sending request in requestToResetPassword_withInValidUsername here] off begin
		// % protected region % [Add any additional logic after sending request in requestToResetPassword_withInValidUsername here] end

		// Test response body
		String expectedError = "unknown_user";
		String expectedErrorDescription = "Could not find the user. Please check your username.";
		RequestUtil.checkErrorResponse(result, expectedError, expectedErrorDescription, HttpStatus.NOT_FOUND);
		
		// % protected region % [Add any additional logic after sending asserts in requestToResetPassword_withInValidUsername here] off begin
		// % protected region % [Add any additional logic after sending asserts in requestToResetPassword_withInValidUsername here] end
	}

	@Test
	public void requestToResetPassword_missingUserName() throws Exception{

		Map<String, Object> body = new HashMap<>();
		
		// % protected region % [Add any additional request parameters in requestToResetPassword_missingUserName here] off begin
		// % protected region % [Add any additional request parameters in requestToResetPassword_missingUserName here] end

		ResultActions result = RequestUtil.sendRequestByEndpointWithJsonBody(mvc, requestResetPasswordEndpoint, body);

		// % protected region % [Add any additional logic after sending request in requestToResetPassword_missingUserName here] off begin
		// % protected region % [Add any additional logic after sending request in requestToResetPassword_missingUserName here] end

		// Test the response.
		String errorType = "missing_arguments";
		String errorDescription = "Username is required";
		RequestUtil.checkErrorResponse(result, errorType, errorDescription, HttpStatus.BAD_REQUEST);

		// % protected region % [Add any additional asserts in requestToResetPassword_missingUserName here] off begin
		// % protected region % [Add any additional asserts in requestToResetPassword_missingUserName here] end
	}

	@Test
	public void testResetPassword_withMissingArguments() throws Exception {
		String username =  "admin@example.com";
		String newPassword = "new_password";
		Map<String, Object> body = new HashMap<>();

		body.put("username", username);
		body.put("password", newPassword);

		// % protected region % [Add any additional logic before sending response in testResetPassword_withMissingArguments here] off begin
		// % protected region % [Add any additional logic before sending response in testResetPassword_withMissingArguments here] end

		ResultActions result = RequestUtil.sendRequestByEndpointWithJsonBody(mvc, resetPasswordEndpoint, body);

		// % protected region % [Add any additional logic after sending response in testResetPassword_withMissingArguments here] off begin
		// % protected region % [Add any additional logic after sending response in testResetPassword_withMissingArguments here] end

		String expectedError = "missing_arguments";
		String expectedErrorDescription = "Token is missing from the request.";

		// % protected region % [Add any additional logic before RequestUtil.checkErrorResponse in testResetPassword_withMissingArguments here] off begin
		// % protected region % [Add any additional logic before RequestUtil.checkErrorResponse in testResetPassword_withMissingArguments here] end

		RequestUtil.checkErrorResponse(result, expectedError, expectedErrorDescription, HttpStatus.BAD_REQUEST);
	
		// % protected region % [Add any additional asserts in testResetPassword_withMissingArguments here] off begin
		// % protected region % [Add any additional asserts in testResetPassword_withMissingArguments here] end
	}

	/**
	 * Sending a mock request to reuqest to reeset password
	 * @param username Username to reset password
	 * @throws Exception Exception thrown when trying to send request
	 */
	private ResultActions sendToRequestResetPassword(String username) throws Exception {
		Map<String, Object> body = new HashMap<>();
		body.put("username", username);

		// % protected region % [Add any additional logic before sending request in sendToRequestResetPassword here] off begin
		// % protected region % [Add any additional logic before sending request in sendToRequestResetPassword here] end

		ResultActions result = RequestUtil.sendRequestByEndpointWithJsonBody(mvc, requestResetPasswordEndpoint, body);

		// % protected region % [Add any additional logic after sending request in sendToRequestResetPassword here] off begin
		// % protected region % [Add any additional logic after sending request in sendToRequestResetPassword here] end

		return result;
	}

	/**
	 * Check Whether email is sent, and content in email
	 * @throws MessagingException Error being thrown by SMTP server.
	 */
	private void checkResetPasswordEmail(String username, String email, TokenEntity tokenEntity) throws MessagingException {
		// % protected region % [Add any additional logic before checkResetPasswordEmail here] off begin
		// % protected region % [Add any additional logic before checkResetPasswordEmail here] end
		
		// Check Smtp Server and get email
		MimeMessage[] receivedMessages = smtpServerRule.getMessages();
		Assert.assertEquals(1, receivedMessages.length);
		MimeMessage resetPasswordEmail = receivedMessages[0];
		Assert.assertEquals("Reset Password", resetPasswordEmail.getSubject());
		String emailContent = GreenMailUtil.getBody(resetPasswordEmail);

		String greetingMessage = String.format("Hi %s,", username);
		Assert.assertTrue(emailContent.contains(greetingMessage));

		String resetPasswordUrl = generateResetPasswordUrl(tokenEntity, email);
		Assert.assertTrue(emailContent.contains(String.format("<a class=\"btn\" href=\"%s\">Reset Password</a>", resetPasswordUrl)));

		// % protected region % [Add any additional logic after checkResetPasswordEmail here] off begin
		// % protected region % [Add any additional logic after checkResetPasswordEmail here] end
	}

	/**
	 * Generate token for reset password token in client side
	 */
	private String generateResetPasswordUrl(TokenEntity tokenEntity, String username) {
		String url = String.format("%s/reset-password?token=%s&username=%s", clientsideHost, tokenEntity.getToken(), username);
		
		// % protected region % [Add any additional logic in generateResetPasswordUrl here] off begin
		// % protected region % [Add any additional logic in generateResetPasswordUrl here] end

		return url;
	}

	/**
	 * Check whether whether could use cookie in response for authentication
	 * @param httpServletResponse Response after reset password
	 * @param username
	 */
	private void checkUserLoggedIn(MockHttpServletResponse httpServletResponse, String username) {

		MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();

		httpServletRequest.setCookies(httpServletResponse.getCookies());

		// Check whether user is authenticated in server with cookie in response
		Authentication authentication =  this.authenticationService.getAuthentication(httpServletRequest);
		Assert.assertEquals(authentication.getName(), username);

		// Check whther csrf token i valid
		String csrfToken = this.authenticationService.getCsrfToken(httpServletRequest);
		Assert.assertNotNull(csrfToken);

		// % protected region % [Add any additional logic in checkUserLoggedIn here] off begin
		// % protected region % [Add any additional logic in checkUserLoggedIn here] end
	}

	// % protected region % [Add any additional methods here] off begin
	// % protected region % [Add any additional methods here] end
}
