package groupproject.backend.service.impl;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import groupproject.backend.dto.TransactionRequestDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.TransactionService;

@Service
public class TransactionServiceImpl implements TransactionService {

    private final TransactionRepository transactionRepository;
    private final UserRepository userRepository;

    public TransactionServiceImpl(TransactionRepository transactionRepository, UserRepository userRepository) {
        this.transactionRepository = transactionRepository;
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public ApiResponse<TransactionResponseDTO> addTransaction(Authentication authentication, TransactionRequestDTO request) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Transaction transaction = Transaction.builder()
                .user(user)
                .type(request.getType())
                .amount(request.getAmount())
                .description(request.getDescription())
                .build();

        Transaction saved = Objects.requireNonNull(transactionRepository.save(transaction), "Failed to save transaction");

        return ApiResponse.success(mapToDTO(saved), "Transaction added successfully");
    }

    @Override
    public ApiResponse<List<TransactionResponseDTO>> getMyTransactions(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        List<TransactionResponseDTO> transactions = transactionRepository
                .findByUserOrderByCreatedAtDesc(user)
                .stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());

        return ApiResponse.success(transactions, "Transactions retrieved");
    }

    private TransactionResponseDTO mapToDTO(Transaction transaction) {
        return TransactionResponseDTO.builder()
                .id(transaction.getId())
                .type(transaction.getType())
                .amount(transaction.getAmount())
                .description(transaction.getDescription())
                .transactionDate(transaction.getTransactionDate())
                .createdAt(transaction.getCreatedAt())
                .build();
    }
}
