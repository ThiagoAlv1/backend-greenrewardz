package br.com.backendgreenrewardz.backend.infra.security.configurations;


import br.com.backendgreenrewardz.backend.infra.security.TokenService;
import br.com.backendgreenrewardz.backend.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    @Autowired
    TokenService tokenService;
    @Autowired
    UserRepository userRepository;

    // Sobrescreve o método doFilterInternal, que define a lógica do filtro que será aplicada a cada requisição HTTP.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Recupera o token de autenticação do cabeçalho da requisição.
        var token = this.recoverToken(request);
        if(token != null){
            // Valida o token e recupera o login (nome de usuário) associado.
            var login = tokenService.validateToken(token);
            // Busca os detalhes do usuário a partir do login.
            UserDetails user = userRepository.findByLogin(login);

            // Cria um objeto de autenticação com os detalhes do usuário e suas autoridades (roles).
            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            // Define o objeto de autenticação no contexto de segurança do Spring Security.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // Continua a execução da cadeia de filtros, permitindo que outras partes do filtro ou do servlet sejam executadas.
        filterChain.doFilter(request, response);
    }

    // Método auxiliar para recuperar o token JWT do cabeçalho 'Authorization' da requisição HTTP.
    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        // Extrai o token, removendo o prefixo "Bearer ".
        return authHeader.replace("Bearer ", "");
    }
}
