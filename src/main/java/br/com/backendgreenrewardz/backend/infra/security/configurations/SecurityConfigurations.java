package br.com.backendgreenrewardz.backend.infra.security.configurations;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Marca a classe como uma fonte de configuração de beans do Spring e habilita a segurança web no aplicativo Spring.
@Configuration
@EnableWebSecurity
public class SecurityConfigurations {
    // Injeta um filtro de segurança personalizado para ser usado na cadeia de filtros de segurança.
    @Autowired
    SecurityFilter securityFilter;

    // Define e configura a cadeia de filtros de segurança que será aplicada às requisições HTTP.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return  httpSecurity
                // Desabilita a proteção CSRF (Cross-Site Request Forgery). É comum desabilitar em APIs REST.
                .csrf(csrf -> csrf.disable())
                // Configura o gerenciamento de sessão para ser sem estado, pois a autenticação será feita via token.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configura regras de autorização para endpoints específicos.
                .authorizeHttpRequests(authorize -> authorize
                        // Permite todos os acessos aos endpoints de login e registro sem autenticação.
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register" ).permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // Qualquer outra requisição precisa ser autenticada.
                        .anyRequest().authenticated()
                )
                // Adiciona o filtro de segurança personalizado antes do filtro padrão de autenticação de usuário e senha.
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
                // Constrói a cadeia de filtros com as configurações definidas.
                .build();
    }

    // Expõe o AuthenticationManager como um bean do Spring para ser usado em outras partes da aplicação.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Define o bean do codificador de senha que será usado para criptografar e verificar as senhas dos usuários.
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
