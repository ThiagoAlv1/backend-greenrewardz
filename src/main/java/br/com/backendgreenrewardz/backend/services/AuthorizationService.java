package br.com.backendgreenrewardz.backend.services;

import br.com.backendgreenrewardz.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService implements UserDetailsService {

    @Autowired
    UserRepository repository;

    // Sobrescreve o método loadUserByUsername da interface UserDetailsService.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Tenta encontrar um usuário pelo seu login (username) usando o repositório.
        UserDetails user = repository.findByLogin(username);

        // Se nenhum usuário for encontrado, lança uma exceção indicando que o usuário não foi encontrado.
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        // Retorna os detalhes do usuário encontrado, que contêm informações necessárias para autenticação e autorização.
        return user;
    }
}
