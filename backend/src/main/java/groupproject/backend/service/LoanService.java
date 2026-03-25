package groupproject.backend.service;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import org.springframework.security.core.Authentication;

import groupproject.backend.dto.LoanDecisionRequestDTO;
import groupproject.backend.dto.LoanRequestDTO;
import groupproject.backend.dto.LoanResponseDTO;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.response.PagedResponse;

public interface LoanService {
    ApiResponse<LoanResponseDTO> applyLoan(Authentication authentication, LoanRequestDTO request);
    ApiResponse<List<LoanResponseDTO>> getMyLoans(Authentication authentication);
    ApiResponse<LoanResponseDTO> getLoanByIdForUser(Authentication authentication, UUID loanId);
    ApiResponse<List<LoanResponseDTO>> getAllLoans();
    ApiResponse<List<LoanResponseDTO>> getPendingLoans();
    ApiResponse<LoanResponseDTO> decideLoan(Authentication authentication, UUID loanId, LoanDecisionRequestDTO request);

    /**
     * Paginated + filtered loan query for admin panel.
     * All params are optional (null = no filter).
     */
    ApiResponse<PagedResponse<LoanResponseDTO>> getLoansFiltered(
            int page, int size,
            String status,
            String riskLevel,
            LocalDate fromDate,
            LocalDate toDate);
}
