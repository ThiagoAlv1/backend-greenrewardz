package br.com.backendgreenrewardz.backend.controllers;



import br.com.backendgreenrewardz.backend.domain.user.AuthenticationDTO;
import br.com.backendgreenrewardz.backend.domain.user.LoginResponseDTO;
import br.com.backendgreenrewardz.backend.domain.user.RegisterDTO;
import br.com.backendgreenrewardz.backend.domain.user.User;
import br.com.backendgreenrewardz.backend.services.TokenService;
import br.com.backendgreenrewardz.backend.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

// Define a classe como um controlador REST, permitindo que ela lide com requisições HTTP.
@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository repository;

    @Autowired
    private TokenService tokenService;

    // Método para tratar POST requests no caminho "/auth/login", para autenticar usuários.
    @PostMapping("/login")
    @CrossOrigin(origins = "*")
    public ResponseEntity login(@RequestBody @Valid AuthenticationDTO data) {
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
        var auth = this.authenticationManager.authenticate(usernamePassword);

        var token = tokenService.generateToken((User) auth.getPrincipal());

        // Retorna uma resposta HTTP 200 OK com o token JWT no corpo da resposta.
        return ResponseEntity.ok(new LoginResponseDTO(token));
    }

    // Método para tratar POST requests no caminho "/auth/register", para registrar novos usuários.
    @PostMapping("/register")
    @CrossOrigin(origins = "*")
    public ResponseEntity<String> register(@RequestBody @Valid RegisterDTO data, UriComponentsBuilder uriBuilder) {
        if (this.repository.findByLogin(data.login()) != null) {
            return ResponseEntity.badRequest().body("Usuário já existe.");
        }

        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        User newUser = new User(data.login(), encryptedPassword, data.role());

        this.repository.save(newUser);

        // Construindo a URI do recurso criado para incluir no cabeçalho 'Location'
        var location = uriBuilder.path("/users/{id}")
                .buildAndExpand(newUser.getId())
                .toUri();

        // Retorna uma resposta HTTP 201 Created com a localização do novo recurso no cabeçalho 'Location'
        return ResponseEntity.created(location).body("Cadastrado com sucesso!");
    }
}

