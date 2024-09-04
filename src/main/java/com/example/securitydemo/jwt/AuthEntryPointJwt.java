package com.example.securitydemo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 AuthEntryPointJwt
 → Provides custom handling for
 unauthorized requests, typically
 when authentication is required
 but not supplied or valid.
 → When an unauthorized
 request is detected, it logs the
 error and returns a JSON
 response with an error message,
 status code, and the path
 attempted.
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

}

/**
 Annotations
 @Component: This annotation indicates that the class is a Spring component, allowing Spring to automatically detect and register it as a bean in the application context.
 Class Implementation
 implements AuthenticationEntryPoint: This indicates that the class implements the AuthenticationEntryPoint interface, which is used to handle authentication errors.
 Fields
 Logger logger: A logger instance for logging messages.

 Methods
     commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException):
 This method is overridden from the AuthenticationEntryPoint interface and is called whenever an authentication exception occurs.
     logger.error(“Unauthorized error: {}”, authException.getMessage()): Logs the unauthorized error message for debugging purposes.
     response.setContentType(MediaType.APPLICATION_JSON_VALUE): Sets the content type of the response to JSON.
     response.setStatus(HttpServletResponse.SC_UNAUTHORIZED): Sets the HTTP status code to 401 (Unauthorized).
     final Map<String, Object> body = new HashMap<>(): Creates a map to hold the response body.
     body.put(“status”, HttpServletResponse.SC_UNAUTHORIZED): Adds the status code to the response body.
     body.put(“error”, “Unauthorized”): Adds an error message to the response body.
     body.put(“message”, authException.getMessage()): Adds the exception message to the response body.
     body.put(“path”, request.getServletPath()): Adds the request path to the response body.
 final ObjectMapper mapper = new ObjectMapper(): Creates an ObjectMapper instance for converting the response body to JSON.
    mapper.writeValue(response.getOutputStream(), body): Writes the response body to the HTTP response output stream in JSON format.
 */