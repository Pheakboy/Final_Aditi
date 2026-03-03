package groupproject.backend.service;

import java.util.List;

import org.springframework.security.core.Authentication;

import groupproject.backend.dto.TransactionRequestDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.response.ApiResponse;

public interface TransactionService {
    ApiResponse<TransactionResponseDTO> addTransaction(Authentication authentication, TransactionRequestDTO request);
    ApiResponse<List<TransactionResponseDTO>> getMyTransactions(Authentication authentication);
}
