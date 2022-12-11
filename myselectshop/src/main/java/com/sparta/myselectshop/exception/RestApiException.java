package com.sparta.myselectshop.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Getter
@Setter
public class RestApiException {
    private String errorMessage;
    private HttpStatus httpStatus;
}