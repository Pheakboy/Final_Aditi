package groupproject.backend.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import groupproject.backend.dto.LoanRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.LoanService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/loans")
public class LoanController {

    private final LoanService loanService;

    public LoanController(LoanService loanService) {
        this.loanService = loanService;
    }

    @PostMapping("/apply")
    public ResponseEntity<ApiResponse<LoanResponseDTO>> applyLoan(
            Authentication authentication,
            @Valid @RequestBody LoanRequestDTO request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(loanService.applyLoan(authentication, request));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<LoanResponseDTO>>> getMyLoans(
            Authentication authentication) {
        return ResponseEntity.ok(loanService.getMyLoans(authentication));
    }
}
