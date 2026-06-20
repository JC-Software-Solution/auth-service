package jcss.soft.com.auth_service.service;


import jcss.soft.com.auth_service.dtos.request.AuthenticateRequest;
import jcss.soft.com.auth_service.dtos.request.RegisterRequest;
import jcss.soft.com.auth_service.dtos.response.AuthenticationResponse;
import jcss.soft.com.auth_service.model.Role;
import jcss.soft.com.auth_service.model.User;
import jcss.soft.com.auth_service.repository.TokenRepository;
import jcss.soft.com.auth_service.repository.UserRepository;
import jcss.soft.com.auth_service.dtos.response.ResponseObject;
import jcss.soft.com.auth_service.token.Token;
import jcss.soft.com.auth_service.token.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static jcss.soft.com.auth_service.constants.Constants.ERROR_STATUS;
import static jcss.soft.com.auth_service.constants.Constants.SUCCESS_STATUS;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepo;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authManager;

    private final TokenRepository tokenRepo;

    public ResponseObject register(RegisterRequest request) {

        Optional<User> userRecord = userRepo.findByEmail(request.getEmail());
        if(userRecord.isPresent()) {
            return new ResponseObject(ERROR_STATUS, "Email already exist", null);
        }
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        User savedUser = userRepo.save(user);

        String token = jwtService.generateToken(user);

        saveUserToken(savedUser, token);

        var tokenData =  AuthenticationResponse.builder().token(token).build();
        return new ResponseObject(SUCCESS_STATUS, "You are successfully registered", tokenData);
    }

    public AuthenticationResponse authenticate(AuthenticateRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        var user = userRepo.findByEmail(request.getEmail())
                .orElseThrow();

        var token = jwtService.generateToken(user);
        revokedAllUserTokens(user);
        saveUserToken(user, token);

        return AuthenticationResponse.builder()
                .token(token).build();

    }

    private void saveUserToken(User savedUser, String token) {

        var tokenData = Token.builder()
                .user(savedUser)
                .token(token)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepo.save(tokenData);

    }

    private void 	revokedAllUserTokens(User user) {
        var validUserTokens = tokenRepo.findAllValidTokensByUser(user.getId());
        if(validUserTokens.isEmpty()) {
            return;
        }

        validUserTokens.forEach( t -> {
            t.setRevoked(true);
            t.setExpired(true);
        });

        tokenRepo.saveAll(validUserTokens);
    }

}
