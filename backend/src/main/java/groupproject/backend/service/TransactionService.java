package groupproject.backend.service;

import groupproject.backend.dto.TransactionRequestDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.response.ApiResponse;
import org.springframework.security.core.Authentication;

import java.time.LocalDate;
import java.util.List;

public interface TransactionService {
    ApiResponse<TransactionResponseDTO> addTransaction(Authentication authentication, TransactionRequestDTO request);
    ApiResponse<List<TransactionResponseDTO>> getMyTransactions(Authentication authentication);
    ApiResponse<List<TransactionResponseDTO>> getMyTransactionsFiltered(Authentication authentication, String type, LocalDate from, LocalDate to);
    byte[] exportTransactionsCsv(Authentication authentication, String type, LocalDate from, LocalDate to);
}
