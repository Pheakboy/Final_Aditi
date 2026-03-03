package groupproject.backend.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.LoanService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final LoanService loanService;

    public AdminController(LoanService loanService) {
        this.loanService = loanService;
    }

    @GetMapping("/loans")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getAllLoans() {
        return ResponseEntity.ok(loanService.getAllLoans());
    }

    @GetMapping("/loans/pending")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getPendingLoans() {
        return ResponseEntity.ok(loanService.getPendingLoans());
    }

    @PostMapping("/loans/{loanId}/decide")
    public ResponseEntity<ApiResponse<LoanResponseDTO>> decideLoan(
            Authentication authentication,
            @PathVariable UUID loanId,
            @Valid @RequestBody LoanDecisionRequestDTO request) {
        return ResponseEntity.ok(loanService.decideLoan(authentication, loanId, request));
    }
}
