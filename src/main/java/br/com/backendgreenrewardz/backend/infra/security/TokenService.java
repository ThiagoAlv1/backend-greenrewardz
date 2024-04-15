package br.com.backendgreenrewardz.backend.infra.security;

import br.com.backendgreenrewardz.backend.domain.user.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    // Método para gerar um token JWT para um usuário específico.
    public String generateToken(User user){
        try{
            // Cria um algoritmo de assinatura usando o segredo configurado.
            Algorithm algorithm = Algorithm.HMAC256(secret);
            // Constrói um token JWT com algumas reivindicações específicas: emissor, assunto e data de expiração.
            String token = JWT.create()
                    .withIssuer("auth-api") // Define o emissor do token.
                    .withSubject(user.getLogin()) // Define o assunto do token, geralmente o identificador do usuário.
                    .withExpiresAt(genExpirationDate()) // Define a data de expiração do token.
                    .sign(algorithm); // Assina o token com o algoritmo especificado.
            return token;
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token", exception);
        }
    }

    // Método para validar um token JWT recebido e extrair o login do usuário (assunto do token).
    public String validateToken(String token){
        try {
            // Cria um algoritmo de verificação usando o mesmo segredo.
            Algorithm algorithm = Algorithm.HMAC256(secret);
            // Configura e executa a verificação do token.
            return JWT.require(algorithm)
                    .withIssuer("auth-api") // Espera que o emissor do token seja "auth-api".
                    .build() // Constrói o verificador do token.
                    .verify(token) // Verifica o token.
                    .getSubject(); // Extrai e retorna o assunto do token (login do usuário).
        } catch (JWTVerificationException exception){
            return "";
        }
    }

    // Método auxiliar para gerar a data de expiração do token, que é duas horas a partir do momento atual.
    private Instant genExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}

