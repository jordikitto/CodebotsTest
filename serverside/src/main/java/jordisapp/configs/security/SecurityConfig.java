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
package jordisapp.configs.security;

import jordisapp.configs.security.authorities.CustomGrantedAuthority;
import jordisapp.configs.security.filters.*;
import jordisapp.configs.security.services.*;
import jordisapp.entities.*;
import jordisapp.repositories.*;
import jordisapp.configs.security.helpers.AnonymousHelper;
import com.google.common.collect.ImmutableList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.*;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.core.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.*;
import org.springframework.web.filter.CorsFilter;

import java.util.*;

// % protected region % [Add any additional imports here] off begin
// % protected region % [Add any additional imports here] end

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	/**
	 * Whitelist URLs which will not require authentication when accessed. However, Spring by default will still require
	 * an {@link org.springframework.security.core.Authentication} object if no logged in is detected.
	 */
	public static final String[] AUTH_WHITELIST = {
			// % protected region % [Add any additional whitelist URL here] off begin
			// % protected region % [Add any additional whitelist URL here] end
			"/api/api-docs",
			"/voyager",
			"/altair",
			"/graphiql",
			"/graphql",
			"/swagger-resources/**",
			"/swagger-ui.html",
			"/v2/api-docs",
			"/webjars/**",
			"/assets/**",
			"/static/",
			"/",
			"/logout",
			"/api/authorization/request-reset-password",
			"/index.html",
			"/{x:(?!api|graphql|voyager|altair|graphiql|swagger-ui.html).*}"
	};

	/**
	 * Key used for anonymous user if not authenticated. Note that this key is not configurable.
	 */
	public static final String ANONYMOUS_KEY = "anonymous";

	/**
	 * Username used for anonymous user if not authenticated. Note that this username is not configurable.
	 */
	public static final UserDetails ANONYMOUS_USERNAME = new User("anonymous@example.com", "anonymous", List.of());

	/**
	 * List of all roles that are applied to anonymous user. By default anonymous user is no different than normal a
	 * unauthenticated user.
	 */
	public static final List<GrantedAuthority> ANONYMOUS_ROLES = ImmutableList.of(
		// % protected region % [Add any additional public roles here] off begin
		// % protected region % [Add any additional public roles here] end
		// Stub authority to satisfy Spring security. This authority does not do anything and is not meant to be used
		// in any meaningful way.
		new CustomGrantedAuthority("ROLE_ANONYMOUS", "", false, false, false, false)
	);

	/**
	 * The anonymous user which will be set by default if there is no logged in user.
	 */
	public static final Authentication ANONYMOUS_USER = new AnonymousAuthenticationToken(
		ANONYMOUS_KEY,
		ANONYMOUS_USERNAME,
		ANONYMOUS_ROLES
	);

	/*
	 * Environment info.
	 */
	private boolean isDevEnvironment;
	private boolean isTestEnvironment;

	/*
	 * Authentication and security info.
	 */
	private final AuthenticationService authService;
	private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;

	/*
	 * User management services.
	 */
	private final UserService userService;
	/*
	 * Base user repository
	 */
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;

	/*
	 * Login and logout handlers.
	 */
	private final AuthenticationSuccessHandler authSuccessHandler;
	private final AuthenticationFailureHandler authFailureHandler;
	private final LogoutSuccessHandler logoutHandler;

	// % protected region % [Add any additional class fields here] off begin
	// % protected region % [Add any additional class fields here] end

	@Autowired
	public SecurityConfig(
			// % protected region % [Add any additional constructor parameters here] off begin
			// % protected region % [Add any additional constructor parameters here] end
			Environment env,
			AuthenticationService authService,
			RestAuthenticationEntryPoint restAuthenticationEntryPoint,
			UserService userService,
			UserRepository userRepository,
			RoleRepository roleRepository,
			AuthenticationSuccessHandler authSuccessHandler,
			AuthenticationFailureHandler authFailureHandler,
			LogoutSuccessHandler logoutHandler
	) {
		// % protected region % [Add any additional constructor logic before the main body here] off begin
		// % protected region % [Add any additional constructor logic before the main body here] end

		for (int i = 0; i < env.getActiveProfiles().length; ++i) {
			if (env.getActiveProfiles()[i].equals("dev")) {
				isDevEnvironment = true;
			} else if (env.getActiveProfiles()[i].equals("test")) {
				isTestEnvironment = true;
			}
		}

		// % protected region % [Add any additional constructor logic here] off begin
		// % protected region % [Add any additional constructor logic here] end

		this.authService = authService;
		this.restAuthenticationEntryPoint = restAuthenticationEntryPoint;
		this.userService = userService;
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.authSuccessHandler = authSuccessHandler;
		this.authFailureHandler = authFailureHandler;
		this.logoutHandler = logoutHandler;

		// % protected region % [Add any additional constructor logic after the main body here] off begin
		// % protected region % [Add any additional constructor logic after the main body here] end
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// % protected region % [Add any additional security configuration before the main body here] off begin
		// % protected region % [Add any additional security configuration before the main body here] end

		if (isDevEnvironment || isTestEnvironment) {
			// % protected region % [Add any additional security configuration for dev and test environments before the main body here] off begin
			// % protected region % [Add any additional security configuration for dev and test environments before the main body here] end

			http.cors().and().csrf().disable();

			// % protected region % [Add any additional security configuration for dev and test environments after the main body here] off begin
			// % protected region % [Add any additional security configuration for dev and test environments after the main body here] end
	} else {
			// % protected region % [Add any additional security configuration for other environments before the main body here] off begin
			// % protected region % [Add any additional security configuration for other environments before the main body here] end

			http
					.csrf()
					.and()
					.requiresChannel()
					.antMatchers("/**").requiresSecure();

			// % protected region % [Add any additional security configuration for other environments after the main body here] off begin
			// % protected region % [Add any additional security configuration for other environments after the main body here] end
		}

		// % protected region % [Add any additional security configuration here] off begin
		// % protected region % [Add any additional security configuration here] end

		http
				.authorizeRequests()
				.antMatchers(AUTH_WHITELIST).permitAll()
				.anyRequest().authenticated()
				.and()
				.formLogin()
					.loginPage("/login")
					.loginProcessingUrl("/auth/login")
					.successHandler(authSuccessHandler)
					.failureHandler(authFailureHandler)
				.and()
				.logout()
					.logoutUrl("/auth/logout")
					.logoutSuccessHandler(logoutHandler)
					.invalidateHttpSession(true)
					.deleteCookies("AUTH-TOKEN")
					.deleteCookies("XSRF-TOKEN")
				.and()
				.anonymous()
				.and()
				// % protected region % [Add any additional filters before the main ones here] off begin
				// % protected region % [Add any additional filters before the main ones here] end
				.addFilterBefore(
						new ResetPasswordFilter(
								"/api/authorization/reset-password",
								userService,
								authSuccessHandler,
								passwordEncoder(),
								authenticationManager()
						),
						UsernamePasswordAuthenticationFilter.class
				)
				.addFilterBefore(
						new AuthenticationFilter("/graphql", authService),
						UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(
						new AuthenticationFilter("/api/(?!api-docs).*", authService),
						UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(
						new AuthenticationFilter("/docs/.*", authService),
						UsernamePasswordAuthenticationFilter.class)
				// % protected region % [Add any additional filters after the main ones here] off begin
				// % protected region % [Add any additional filters after the main ones here] end
				.exceptionHandling()
				.authenticationEntryPoint(restAuthenticationEntryPoint);

		// % protected region % [Add any additional security configuration after the main body here] off begin
		// % protected region % [Add any additional security configuration after the main body here] end
	}

	@Bean
	@Profile("dev")
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.addAllowedMethod("OPTIONS");
		config.addAllowedMethod("GET");
		config.addAllowedMethod("POST");
		config.addAllowedMethod("PUT");
		config.addAllowedMethod("DELETE");
		source.registerCorsConfiguration("/**", config);
		return new CorsFilter(source);
	}

	/**
	 * @inheritDoc
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// % protected region % [Add any additional logic for configure before the main body here] off begin
		// % protected region % [Add any additional logic for configure before the main body here] end

		auth
				// % protected region % [Add any additional configurations for the authentication manager here] off begin
				// % protected region % [Add any additional configurations for the authentication manager here] end
				.authenticationProvider(authenticationProvider())
				.jdbcAuthentication();

		// % protected region % [Add any additional logic for configure after the main body here] off begin
		// % protected region % [Add any additional logic for configure after the main body here] end
	}

	/**
	 * Authentication provider to be used in the authentication process. This differs from the default provider due to
	 * the custom {@link UserService} that handles authenticating users.
	 */
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		// % protected region % [Add any additional logic for authenticationProvider before the main body here] off begin
		// % protected region % [Add any additional logic for authenticationProvider before the main body here] end

		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userService);
		authProvider.setPasswordEncoder(passwordEncoder());

		// % protected region % [Add any additional logic for authenticationProvider after the main body here] off begin
		// % protected region % [Add any additional logic for authenticationProvider after the main body here] end

		return authProvider;
	}

	/**
	 * Password encoder used to encode user password during registration process.
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		// % protected region % [Update password encoder configuration here] off begin
		return new BCryptPasswordEncoder(11);
		// % protected region % [Update password encoder configuration here] end
	}

	/**
	 * Filter used to log request info for every request that reaches the server side.
	 */
	@Bean
	public RequestLoggingFilter logFilter() {
		// % protected region % [Update request logging configuration here] off begin
		return new RequestLoggingFilter();
		// % protected region % [Update request logging configuration here] end
	}

	/**
	 * Create default roles and privileges to be associated with users. Note that this method does not take anonymous
	 * roles into account. Instead it is deferred to {@link AuthenticationFilter}.
	 */
	@EventListener(value = ApplicationReadyEvent.class)
	public void setupRolesAndPrivileges() {
		AnonymousHelper.runAnonymously(() -> {
			Map<String, RoleEntity> unsavedRoles = new HashMap<>();
			Map<String, RoleEntity> savedRoles = new HashMap<>();


			if (isDevEnvironment || isTestEnvironment) {
				setupTestAccounts(savedRoles);
				// % protected region % [Add any additional dev and test setup here] off begin
				// % protected region % [Add any additional dev and test setup here] end
			}
		});
	}

	/**
	 * Create a privilege for the role
	 * If privilege is already exists, create a new one
	 * @param roleEntity Related role entity
	 * @param entityName Name of target entity
	 * @param privilegeName Name of the privliege entity
	 * @param allowCreate whether allow to create
	 * @param allowRead whether allow to read
	 * @param allowUpdate whether allow to update
	 * @param allowDelete whether allow to delete
	 */
	private void createOrUpdatePrivilege(RoleEntity roleEntity, String entityName, String privilegeName,
										 Boolean allowCreate, Boolean allowRead, Boolean allowUpdate, Boolean allowDelete) {

		PrivilegeEntity privilegeEntity = roleEntity.getPrivileges().stream()
				.filter(privilege ->  privilege.getName().equals(privilegeName))
				.findFirst().orElse(null);

		if (privilegeEntity == null) {
			privilegeEntity = new PrivilegeEntity();
			privilegeEntity.setId(UUID.randomUUID());
			privilegeEntity.setName(privilegeName);
			privilegeEntity.setTargetEntity(entityName);
			roleEntity.getPrivileges().add(privilegeEntity);
		}

		privilegeEntity.setAllowCreate(allowCreate);
		privilegeEntity.setAllowRead(allowRead);
		privilegeEntity.setAllowUpdate(allowUpdate);
		privilegeEntity.setAllowDelete(allowDelete);
	}

	/**
	 * Setup test accounts for ease of development.
	 */
	private void setupTestAccounts(Map<String, RoleEntity> savedRoles) {
		// Create a super user. A super user has all the roles in application
		UserEntity superUser;
		if (userRepository.findByEmail("super@example.com").isEmpty()) {
			superUser = new UserEntity();
			superUser.setEmail("super@example.com");
			superUser.setUsername("super@example.com");
			superUser.setPassword(passwordEncoder().encode("password"));
			superUser.setFirstName("Super");
			superUser.setLastName("Administor");
			superUser.setIsArchived(false);

		} else {
			superUser = (UserEntity)  userRepository.findByEmail("super@example.com").get();
		}

		savedRoles.forEach((roleName, role) -> {
			superUser.addRoles(role);
		});

		userRepository.save(superUser);
	}

	// % protected region % [Add any additional class methods here] off begin
	// % protected region % [Add any additional class methods here] end
}
