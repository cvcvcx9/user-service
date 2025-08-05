package com.cvcvcx.user_service.controller;

import com.cvcvcx.user_service.dto.GoogleLoginRequestDto;
import com.cvcvcx.user_service.dto.LoginRequestDto;
import com.cvcvcx.user_service.dto.RegisterRequestDto;
import com.cvcvcx.user_service.jwt.JwtUtil;
import com.cvcvcx.user_service.model.RefreshToken;
import com.cvcvcx.user_service.model.User;
import com.cvcvcx.user_service.model.UserRole;
import com.cvcvcx.user_service.service.RefreshTokenService;
import com.cvcvcx.user_service.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/register/mobile")
    public ResponseEntity<?> registerUserForMobile(@RequestBody RegisterRequestDto registerRequest) {
        String email = registerRequest.getEmail();
        String password = registerRequest.getPassword();

        if (email == null || password == null || email.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body("Email and password are required.");
        }

        if (userService.findByEmail(email).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already registered.");
        }

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setPassword(password);
        newUser.setProvider("local");
        newUser.setRoles(Collections.singleton(UserRole.USER));

        userService.save(newUser);

        String accessToken = jwtUtil.generateToken(newUser.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(newUser.getEmail());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken.getToken());

        return ResponseEntity.status(HttpStatus.CREATED).body(tokens);
    }

    @PostMapping("/register/web")
    public ResponseEntity<?> registerUserForWeb(
            @RequestBody RegisterRequestDto registerRequest,
            HttpServletResponse response
    ) {
        String email = registerRequest.getEmail();
        String password = registerRequest.getPassword();

        if (email == null || password == null || email.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body("Email and password are required.");
        }

        if (userService.findByEmail(email).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already registered.");
        }

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setPassword(password);
        newUser.setProvider("local");
        newUser.setRoles(Collections.singleton(UserRole.USER));

        userService.save(newUser);

        String accessToken = jwtUtil.generateToken(newUser.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(newUser.getEmail());

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) (jwtUtil.getRefreshExpiration() / 1000));
        response.addCookie(refreshTokenCookie);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);

        return ResponseEntity.status(HttpStatus.CREATED).body(tokens);
    }


    @PostMapping("/login/mobile")
    public ResponseEntity<?> authenticateUserForMobile(@RequestBody LoginRequestDto loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        if (email == null || password == null) {
            return ResponseEntity.badRequest().body("Email and password are required.");
        }

        Optional<User> userOptional = userService.findByEmail(email);
        if (userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }

        User user = userOptional.get();

        if (!"local".equals(user.getProvider())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Please log in with your " + user.getProvider() + " account.");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }

        String accessToken = jwtUtil.generateToken(user.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken.getToken());

        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/login/web")
    public ResponseEntity<?> authenticateUserForWeb(
            @RequestBody LoginRequestDto loginRequest,
            HttpServletResponse response
    ) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        if (email == null || password == null) {
            return ResponseEntity.badRequest().body("Email and password are required.");
        }

        Optional<User> userOptional = userService.findByEmail(email);
        if (userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }

        User user = userOptional.get();

        if (!"local".equals(user.getProvider())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Please log in with your " + user.getProvider() + " account.");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
        }

        String accessToken = jwtUtil.generateToken(user.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) (jwtUtil.getRefreshExpiration() / 1000));
        response.addCookie(refreshTokenCookie);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);

        return ResponseEntity.ok(tokens);
    }


    @PostMapping("/google/mobile")
    public ResponseEntity<?> authenticateWithGoogleForMobile(@RequestBody GoogleLoginRequestDto googleLoginRequest){
        String googleToken = googleLoginRequest.getToken();

        try {
            Map userInfo = RestClient.create()
                    .get()
                    .uri("https://www.googleapis.com/oauth2/v3/userinfo")
                    .header("Authorization", "Bearer " + googleToken)
                    .retrieve()
                    .body(Map.class);

            if (userInfo == null || !userInfo.containsKey("email")){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Google Token.");
            }

            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");

            Optional<User> userOptional = userService.findByEmail(email);
            User user;

            if (userOptional.isPresent()) {
                user = userOptional.get();
                if (!"google".equals(user.getProvider())) {
                    return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already registered with " + user.getProvider() + ".");
                }
            }
            else {
                user = new User();
                user.setEmail(email);
                user.setPassword(null);
                user.setProvider("google");
                user.setRoles(Collections.singleton(UserRole.USER));
                userService.save(user);
            }

            String accessToken = jwtUtil.generateToken(user.getEmail());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken.getToken());

            return ResponseEntity.ok(tokens);
        }catch (RestClientException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Validation failed: " + e.getMessage());
        }
    }

    @PostMapping("/google/web")
    public ResponseEntity<?> authenticateWithGoogleForWeb(
            @RequestBody GoogleLoginRequestDto googleLoginRequest,
            HttpServletResponse response
    ){
        String googleToken = googleLoginRequest.getToken();

        try {
            Map userInfo = RestClient.create()
                    .get()
                    .uri("https://www.googleapis.com/oauth2/v3/userinfo")
                    .header("Authorization", "Bearer " + googleToken)
                    .retrieve()
                    .body(Map.class);

            if (userInfo == null || !userInfo.containsKey("email")){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Google Token.");
            }

            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");

            Optional<User> userOptional = userService.findByEmail(email);
            User user;

            if (userOptional.isPresent()) {
                user = userOptional.get();
                if (!"google".equals(user.getProvider())) {
                    return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already registered with " + user.getProvider() + ".");
                }
            }
            else {
                user = new User();
                user.setEmail(email);
                user.setPassword(null);
                user.setProvider("google");
                user.setRoles(Collections.singleton(UserRole.USER));
                userService.save(user);
            }

            String accessToken = jwtUtil.generateToken(user.getEmail());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge((int) (jwtUtil.getRefreshExpiration() / 1000));
            response.addCookie(refreshTokenCookie);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);

            return ResponseEntity.ok(tokens);
        }catch (RestClientException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Validation failed: " + e.getMessage());
        }
    }

    @PostMapping("/refresh/mobile")
    public ResponseEntity<?> refreshTokenForMobile(@RequestBody Map<String, String> body) {
        String requestRefreshToken = body.get("refreshToken");

        if (requestRefreshToken == null || requestRefreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Refresh token is required.");
        }

        final String finalRequestRefreshToken = requestRefreshToken;

        return refreshTokenService.findByToken(finalRequestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String accessToken = jwtUtil.generateToken(user.getEmail());
                    Map<String, String> responseBody = new HashMap<>();
                    responseBody.put("accessToken", accessToken);
                    responseBody.put("refreshToken", finalRequestRefreshToken);
                    return ResponseEntity.ok(responseBody);
                })
                .orElseGet(() -> {
                    Map<String, String> errorBody = new HashMap<>();
                    errorBody.put("message", "Invalid Refresh Token.");
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorBody);
                });
    }

    @PostMapping("/refresh/web")
    public ResponseEntity<?> refreshTokenForWeb(HttpServletRequest request) {
        String requestRefreshToken = null;

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    requestRefreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (requestRefreshToken == null || requestRefreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Refresh token is required from cookie.");
        }

        final String finalRequestRefreshToken = requestRefreshToken;

        return refreshTokenService.findByToken(finalRequestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String accessToken = jwtUtil.generateToken(user.getEmail());
                    Map<String, String> responseBody = new HashMap<>();
                    responseBody.put("accessToken", accessToken);
                    return ResponseEntity.ok(responseBody);
                })
                .orElseGet(() -> {
                    Map<String, String> errorBody = new HashMap<>();
                    errorBody.put("message", "Invalid Refresh Token.");
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorBody);
                });
    }
}