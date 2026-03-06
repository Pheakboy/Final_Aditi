package groupproject.backend.service.impl;

import groupproject.backend.dto.TransactionRequestDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.TransactionType;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.TransactionService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

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
        User user = getUser(authentication);
        Transaction transaction = Transaction.builder()
                .user(user)
                .type(request.getType())
                .amount(request.getAmount())
                .description(request.getDescription())
                .build();
        Transaction saved = Objects.requireNonNull(transactionRepository.save(transaction));
        return ApiResponse.success(mapToDTO(saved), "Transaction added successfully");
    }

    @Override
    public ApiResponse<List<TransactionResponseDTO>> getMyTransactions(Authentication authentication) {
        return getMyTransactionsFiltered(authentication, null, null, null);
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<List<TransactionResponseDTO>> getMyTransactionsFiltered(
            Authentication authentication, String type, LocalDate from, LocalDate to) {
        User user = getUser(authentication);
        List<Transaction> all = transactionRepository.findByUserOrderByCreatedAtDesc(user);
        List<TransactionResponseDTO> filtered = all.stream()
                .filter(t -> {
                    if (type != null && !type.isBlank()) {
                        try {
                            if (!t.getType().equals(TransactionType.valueOf(type.toUpperCase()))) return false;
                        } catch (IllegalArgumentException ignored) { return false; }
                    }
                    if (from != null && t.getTransactionDate() != null && t.getTransactionDate().isBefore(from)) return false;
                    if (to != null && t.getTransactionDate() != null && t.getTransactionDate().isAfter(to)) return false;
                    return true;
                })
                .map(this::mapToDTO)
                .collect(Collectors.toList());
        return ApiResponse.success(filtered, "Transactions retrieved");
    }

    @Override
    @Transactional(readOnly = true)
    public byte[] exportTransactionsCsv(Authentication authentication, String type, LocalDate from, LocalDate to) {
        ApiResponse<List<TransactionResponseDTO>> result = getMyTransactionsFiltered(authentication, type, from, to);
        StringBuilder sb = new StringBuilder("Date,Type,Amount,Description\n");
        for (TransactionResponseDTO t : result.getData()) {
            sb.append(csvEscape(t.getTransactionDate() != null ? t.getTransactionDate().toString() : "")).append(",");
            sb.append(csvEscape(t.getType() != null ? t.getType().name() : "")).append(",");
            sb.append(t.getAmount()).append(",");
            sb.append(csvEscape(t.getDescription() != null ? t.getDescription() : "")).append("\n");
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String csvEscape(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private User getUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
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
