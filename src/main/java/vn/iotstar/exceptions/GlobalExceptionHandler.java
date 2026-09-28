package vn.iotstar.exceptions;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(Exception.class)
	public ProblemDetail handleSecurityException(Exception exception) {
		ProblemDetail errorDetail;

		if (exception instanceof BadCredentialsException) {
			errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());
			errorDetail.setProperty("description", "The username or password is incorrect");
			return errorDetail;
		}
		if (exception instanceof AccountStatusException) {
			errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, exception.getMessage());
			errorDetail.setProperty("description", "The account is locked");
			return errorDetail;
		}
		if (exception instanceof AccessDeniedException) {
			errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, exception.getMessage());
			errorDetail.setProperty("description", "You are not authorized to access this resource");
			return errorDetail;
		}
		if (exception instanceof TokenExpiredException) {
			errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());
			errorDetail.setProperty("description", "The JWT token has expired");
			return errorDetail;
		}
		if (exception instanceof InvalidTokenException) {
			errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());
			errorDetail.setProperty("description", "The JWT token is invalid");
			return errorDetail;
		}
		if (exception instanceof DataIntegrityViolationException) {
			errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Email already exists");
			errorDetail.setProperty("description", "The email is already registered");
			return errorDetail;
		}

		exception.printStackTrace();
		errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
		errorDetail.setProperty("description", "Unknown internal server error");
		return errorDetail;
	}
}
