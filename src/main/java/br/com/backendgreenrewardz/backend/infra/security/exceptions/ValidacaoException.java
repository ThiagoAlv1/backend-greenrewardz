package br.com.backendgreenrewardz.backend.infra.security.exceptions;

public class ValidacaoException extends RuntimeException {
    public ValidacaoException(String mensagem) {
        super(mensagem);
    }
}
