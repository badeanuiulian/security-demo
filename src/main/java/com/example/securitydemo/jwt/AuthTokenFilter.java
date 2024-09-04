package com.example.securitydemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 AuthTokenFilter
 → Filters incoming requests to
 check for a valid JWT in the
 header, setting the
 authentication context if the
 token is valid.
 → Extracts JWT from request
 header, validates it, and
 configures the Spring Security
 context with user details if the
 token is valid.
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}

/**
 Annotations
 @Component: This annotation indicates that the class is a Spring component, allowing Spring to automatically detect and register it as a bean in the application context.
 Fields
 JwtUtils jwtUtils: A utility class for handling JWT operations like generating and validating tokens.
 UserDetailsService userDetailsService: A service for loading user-specific data.
 Logger logger: A logger instance for logging messages.

 Methods
      doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain):
 This method is overridden from OncePerRequestFilter and is called once per request within a single request thread.
      logger.debug(“AuthTokenFilter called for URI: {}”, request.getRequestURI()): Logs the URI of the incoming request for debugging purposes.
      parseJwt(request): Extracts the JWT token from the request header.
      jwtUtils.validateJwtToken(jwt): Validates the extracted JWT token.
      jwtUtils.getUserNameFromJwtToken(jwt): Retrieves the username from the validated JWT token.
      userDetailsService.loadUserByUsername(username): Loads the user details using the username.
      UsernamePasswordAuthenticationToken authentication: Creates an authentication token with the user details and authorities.
      authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)): Sets additional details about the authentication request.
      SecurityContextHolder.getContext().setAuthentication(authentication): Sets the authentication in the security context.
      filterChain.doFilter(request, response): Continues the filter chain.

 parseJwt(HttpServletRequest request):
     jwtUtils.getJwtFromHeader(request): Extracts the JWT token from the Authorization header of the HTTP request.
     logger.debug(“AuthTokenFilter.java: {}”, jwt): Logs the extracted JWT token for debugging purposes.
     Returns the extracted JWT token.

 */

