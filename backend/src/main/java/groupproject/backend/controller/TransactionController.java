package groupproject.backend.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import groupproject.backend.dto.TransactionRequestDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.TransactionService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/transactions")
public class TransactionController {

    private final TransactionService transactionService;

    public TransactionController(TransactionService transactionService) {
        this.transactionService = transactionService;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<TransactionResponseDTO>> addTransaction(
            Authentication authentication,
            @Valid @RequestBody TransactionRequestDTO request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(transactionService.addTransaction(authentication, request));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<TransactionResponseDTO>>> getMyTransactions(
            Authentication authentication) {
        return ResponseEntity.ok(transactionService.getMyTransactions(authentication));
    }
}
