package groupproject.backend.controller;

import groupproject.backend.dto.TransactionImportResultDTO;
import groupproject.backend.dto.TransactionRequestDTO;
import groupproject.backend.dto.TransactionResponseDTO;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.TransactionImportService;
import groupproject.backend.service.TransactionService;
import jakarta.validation.Valid;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/api/transactions")
public class TransactionController {

    private final TransactionService transactionService;
    private final TransactionImportService transactionImportService;

    public TransactionController(TransactionService transactionService,
                                  TransactionImportService transactionImportService) {
        this.transactionService = transactionService;
        this.transactionImportService = transactionImportService;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<TransactionResponseDTO>> addTransaction(
            Authentication authentication,
            @Valid @RequestBody TransactionRequestDTO request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(transactionService.addTransaction(authentication, request));
    }

    @PostMapping(value = "/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponse<TransactionImportResultDTO>> importTransactions(
            Authentication authentication,
            @RequestParam("file") MultipartFile file) {
        return ResponseEntity.ok(transactionImportService.importFromFile(authentication, file));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<TransactionResponseDTO>>> getMyTransactions(
            Authentication authentication,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
        return ResponseEntity.ok(transactionService.getMyTransactionsFiltered(authentication, type, from, to));
    }
}
