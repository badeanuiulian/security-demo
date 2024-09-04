package com.example.securitydemo;
import com.example.securitydemo.jwt.AuthEntryPointJwt;
import com.example.securitydemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

/**
 SecurityConfig
 → Configures Spring Security
 filters and rules for the
 application
 → Sets up the security filter
 chain, permitting or denying
 access based on paths and roles.
 It also configures session
 management to stateless, which
 is crucial for JWT usage.
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated());
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS)
        );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        //http.httpBasic(withDefaults());
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                )
        );
        http.csrf(csrf -> csrf.disable());
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("password1"))
                    .roles("USER")
                    .build();
            UserDetails admin = User.withUsername("admin")
                    //.password(passwordEncoder().encode("adminPass"))
                    .password(passwordEncoder().encode("adminPass"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}

/**
Annotations
@Configuration: Indicates that the class has @Bean definition methods. Spring will process the class to generate Spring Beans.
@EnableWebSecurity: Enables Spring Security’s web security support and provides the Spring MVC integration.
@EnableMethodSecurity: Enables method-level security, allowing the use of annotations like @PreAuthorize and @Secured to secure methods.

Fields
    DataSource dataSource: Injected DataSource bean for database operations.
    AuthEntryPointJwt unauthorizedHandler: Custom handler for unauthorized access attempts.
Beans
    AuthTokenFilter authenticationJwtTokenFilter(): Defines a bean for the JWT authentication filter.
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http): Configures the security filter chain:
    Permits access to /h2-console/** and /signin.
    Requires authentication for all other requests.
    Sets session management to stateless.
    Configures exception handling with a custom unauthorized handler.
    Disables CSRF protection.
    Adds the JWT authentication filter before the UsernamePasswordAuthenticationFilter.

UserDetailsService userDetailsService(DataSource dataSource): Configures a JdbcUserDetailsManager for user details management using the provided DataSource.

CommandLineRunner initData(UserDetailsService userDetailsService): Initializes the database with default users.

PasswordEncoder passwordEncoder(): Defines a bean for password encoding using BCryptPasswordEncoder.

AuthenticationManager authenticationManager(AuthenticationConfiguration builder): Configures the authentication manager.

  Security Configuration Details
  HttpSecurity Configuration:
  authorizeHttpRequests: Configures URL-based authorization.
  sessionManagement: Sets session creation policy to stateless.
  exceptionHandling: Configures custom unauthorized handler.
  headers: Configures frame options to allow same-origin iframes.
  csrf: Disables CSRF protection.
addFilterBefore: Adds the JWT authentication filter before the username-password authentication filter.
 */


