package br.com.backendgreenrewardz.backend.repositories;


import br.com.backendgreenrewardz.backend.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

// Define uma interface que estende JpaRepository, indicando que esta interface é um repositório para a entidade User.
public interface UserRepository extends JpaRepository<User, Long> {
    // Declara um método para buscar um usuário pelo seu login. Este método não é fornecido por JpaRepository e
    // precisa ser implementado pelo Spring Data JPA baseado na convenção de nomenclatura de métodos.
    UserDetails findByLogin(String login);
}

