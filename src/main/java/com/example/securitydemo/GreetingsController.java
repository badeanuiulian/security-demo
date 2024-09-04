package com.example.securitydemo;
import com.example.securitydemo.jwt.JwtUtils;
import com.example.securitydemo.jwt.LoginRequest;
import com.example.securitydemo.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }


    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint(){
        return "Hello, User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello, Admin!";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);

        return ResponseEntity.ok(response);
    }
}

/**
 Annotations
 @RestController: This annotation is a combination of @Controller and @ResponseBody. It indicates that the class handles HTTP requests and the return values of its methods are written directly to the HTTP response body1.
 @Autowired: This annotation is used for dependency injection. It automatically injects the required beans into the class2.
 @GetMapping: This annotation maps HTTP GET requests to specific handler methods.
 @PreAuthorize: This annotation is used to specify method-level security. It ensures that only users with specific roles can access the annotated methods1.
 @PostMapping: This annotation maps HTTP POST requests to specific handler methods.

 Fields
   JwtUtils jwtUtils: A utility class for handling JWT operations like generating and validating tokens.
   AuthenticationManager authenticationManager: Manages authentication processes.

 Methods
 sayHello(): This method is mapped to the /hello endpoint and returns a simple “Hello” string.
 userEndpoint(): This method is mapped to the /user endpoint and is accessible only to users with the USER role. It returns “Hello, User!”.
 adminEndpoint(): This method is mapped to the /admin endpoint and is accessible only to users with the ADMIN role. It returns “Hello, Admin!”.
 Authentication Method
 authenticateUser(LoginRequest loginRequest): This method handles user authentication:
 It attempts to authenticate the user using the provided username and password.
 If authentication fails, it returns a response with a “Bad credentials” message and a NOT_FOUND status.
 If authentication succeeds, it sets the authentication in the security context, generates a JWT token, and returns a response with the username, roles, and JWT token.
 */
