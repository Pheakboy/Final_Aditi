package groupproject.backend.service;

import java.util.List;
import java.util.UUID;

import org.springframework.security.core.Authentication;

import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.response.ApiResponse;

public interface LoanService {
    ApiResponse<LoanResponseDTO> applyLoan(Authentication authentication, LoanRequestDTO request);
    ApiResponse<List<LoanResponseDTO>> getMyLoans(Authentication authentication);
    ApiResponse<List<LoanResponseDTO>> getAllLoans();
    ApiResponse<List<LoanResponseDTO>> getPendingLoans();
    ApiResponse<LoanResponseDTO> decideLoan(Authentication authentication, UUID loanId, LoanDecisionRequestDTO request);
}
