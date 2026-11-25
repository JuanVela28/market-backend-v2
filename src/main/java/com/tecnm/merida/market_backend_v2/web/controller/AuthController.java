package com.tecnm.merida.market_backend_v2.web.controller;

import com.tecnm.merida.market_backend_v2.domain.Client;
import com.tecnm.merida.market_backend_v2.domain.repository.ClientRepository;
import com.tecnm.merida.market_backend_v2.web.security.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "JWT Login endpoint")
public class AuthController {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate user and generate JWT",
            description = "Validates client credentials against BCrypt hash and returns a JWT bearer token",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            examples = @ExampleObject(
                                    name = "Example Login",
                                    value = """
                                            {
                                               "email": "juan.perez@correo.com",
                                               "password": "1234"
                                            }
                                            """
                            )
                    )
            )
    )
    @ApiResponse(responseCode = "200", description = "Authenticated successfully")
    @ApiResponse(responseCode = "401", description = "Invalid credentials")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        Optional<Client> clientOpt = clientRepository.getByEmail(request.getEmail());

        if (clientOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Client client = clientOpt.get();
        if (client.getPassword() == null || !passwordEncoder.matches(request.getPassword(), client.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String token = jwtUtil.generateToken(client.getEmail());
        return ResponseEntity.ok(new LoginResponse(token));
    }
}