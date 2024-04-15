package br.com.backendgreenrewardz.backend.domain.user;

public record RegisterDTO(String login, String password, UserRole role) {
}
