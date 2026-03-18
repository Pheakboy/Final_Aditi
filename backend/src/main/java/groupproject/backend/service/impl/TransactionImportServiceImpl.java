package groupproject.backend.service.impl;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.DateUtil;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import groupproject.backend.dto.TransactionImportResultDTO;
import groupproject.backend.model.Transaction;
import groupproject.backend.model.User;
import groupproject.backend.model.enums.TransactionType;
import groupproject.backend.repository.TransactionRepository;
import groupproject.backend.repository.UserRepository;
import groupproject.backend.response.ApiResponse;
import groupproject.backend.service.TransactionImportService;

@Service
public class TransactionImportServiceImpl implements TransactionImportService {

    private static final int MAX_ROWS = 1000;
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("xlsx", "xls", "csv", "pdf");
    private static final List<DateTimeFormatter> DATE_FORMATTERS = List.of(
            DateTimeFormatter.ofPattern("yyyy-MM-dd"),
            DateTimeFormatter.ofPattern("dd/MM/yyyy"),
            DateTimeFormatter.ofPattern("MM/dd/yyyy"),
            DateTimeFormatter.ofPattern("dd-MM-yyyy"),
            DateTimeFormatter.ofPattern("d/M/yyyy"),
            DateTimeFormatter.ofPattern("d MMM yyyy"),
            DateTimeFormatter.ofPattern("d MMMM yyyy")
    );

    private final TransactionRepository transactionRepository;
    private final UserRepository userRepository;

    public TransactionImportServiceImpl(TransactionRepository transactionRepository,
                                        UserRepository userRepository) {
        this.transactionRepository = transactionRepository;
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public ApiResponse<TransactionImportResultDTO> importFromFile(Authentication authentication,
                                                                   MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No file provided");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || !originalFilename.contains(".")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid file name");
        }

        // Use only the base name to prevent any path traversal issues
        String safeName = new File(originalFilename).getName();
        String ext = safeName.substring(safeName.lastIndexOf('.') + 1).toLowerCase();

        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Unsupported file type. Allowed: .xlsx, .xls, .csv, .pdf");
        }

        User user = getUser(authentication);
        List<String> errors = new ArrayList<>();
        List<ParsedRow> rows;

        try {
            rows = switch (ext) {
                case "xlsx", "xls" -> parseExcel(file, errors);
                case "csv"         -> parseCsv(file, errors);
                case "pdf"         -> parsePdf(file, errors);
                default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported file type");
            };
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "Could not read file: " + e.getMessage());
        }

        if (rows.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "No valid transactions found. Ensure the file matches the expected format.");
        }

        int imported = 0;
        int skipped = errors.size(); // count parse errors as skipped

        for (ParsedRow row : rows) {
            try {
                Transaction tx = Transaction.builder()
                        .user(user)
                        .type(row.type())
                        .amount(row.amount().abs())
                        .description(row.description())
                        .transactionDate(row.date() != null ? row.date() : LocalDate.now())
                        .build();
                transactionRepository.save(tx);
                imported++;
            } catch (Exception e) {
                skipped++;
                if (errors.size() < 20) errors.add("Save error: " + e.getMessage());
            }
        }

        TransactionImportResultDTO result = new TransactionImportResultDTO();
        result.setImported(imported);
        result.setSkipped(skipped);
        result.setErrors(errors.size() > 10 ? errors.subList(0, 10) : errors);

        return ApiResponse.success(result, imported + " transaction(s) imported successfully");
    }

    // ── Excel ────────────────────────────────────────────────────────────────

    /** Column indices resolved from the header row. -1 = not present. */
    private static class ColIndex {
        int date = -1, moneyIn = -1, moneyOut = -1, description = -1, amount = -1, type = -1;
    }

    private ColIndex resolveHeaders(Row headerRow) {
        ColIndex idx = new ColIndex();
        for (Cell cell : headerRow) {
            String raw = getCellString(cell);
            if (raw == null) continue;
            // normalise: lower-case, strip spaces/punctuation
            String h = raw.toLowerCase().replaceAll("[^a-z0-9]", "");
            int col = cell.getColumnIndex();
            switch (h) {
                case "date", "transactiondate", "valuedate", "postingdate", "txdate"
                    -> { if (idx.date < 0) idx.date = col; }
                case "moneyin", "credit", "cr", "deposit", "deposits",
                     "creditamount", "creditamt", "in"
                    -> { if (idx.moneyIn < 0) idx.moneyIn = col; }
                case "moneyout", "debit", "dr", "withdrawal", "withdrawals",
                     "debitamount", "debitamt", "out", "charges", "charge"
                    -> { if (idx.moneyOut < 0) idx.moneyOut = col; }
                case "description", "narration", "details", "particulars",
                     "reference", "remarks", "memo", "transaction", "transactiondetails"
                    -> { if (idx.description < 0) idx.description = col; }
                case "amount", "value", "transactionamount", "amt"
                    -> { if (idx.amount < 0) idx.amount = col; }
                case "type", "transactiontype", "txtype", "crdr"
                    -> { if (idx.type < 0) idx.type = col; }
                // deliberately ignore: balance, ccy, currency, running balance, etc.
                default -> { /* skip */ }
            }
        }
        return idx;
    }

    private List<ParsedRow> parseExcel(MultipartFile file, List<String> errors) throws IOException {
        List<ParsedRow> rows = new ArrayList<>();
        try (Workbook workbook = WorkbookFactory.create(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0);

            // Scan for the header row (first row that contains a date-like column name)
            ColIndex idx = null;
            int headerRowNum = 0;
            for (Row row : sheet) {
                ColIndex candidate = resolveHeaders(row);
                if (candidate.date >= 0 && (candidate.moneyIn >= 0 || candidate.moneyOut >= 0 || candidate.amount >= 0)) {
                    idx = candidate;
                    headerRowNum = row.getRowNum();
                    break;
                }
            }

            // Fallback: no recognised header — assume row 0 is header, positional cols
            if (idx == null) {
                idx = new ColIndex();
                idx.date = 0; idx.description = 1; idx.amount = 2;
                headerRowNum = 0;
            }

            final ColIndex resolvedIdx = idx;
            final int dataStart = headerRowNum + 1;

            for (Row row : sheet) {
                if (row.getRowNum() < dataStart) continue;
                if (row.getRowNum() > dataStart + MAX_ROWS) break;
                try {
                    ParsedRow parsed = parseExcelRow(row, resolvedIdx);
                    if (parsed != null) rows.add(parsed);
                } catch (Exception e) {
                    if (errors.size() < 20) errors.add("Row " + (row.getRowNum() + 1) + ": " + e.getMessage());
                }
            }
        }
        return rows;
    }

    private ParsedRow parseExcelRow(Row row, ColIndex idx) {
        LocalDate  date        = idx.date        >= 0 ? parseDateFromCell(row.getCell(idx.date))           : null;
        String     description = idx.description >= 0 ? getCellString(row.getCell(idx.description))        : null;

        // ── Separate Money In / Money Out columns (bank statement format) ──────
        if (idx.moneyIn >= 0 || idx.moneyOut >= 0) {
            BigDecimal moneyIn  = idx.moneyIn  >= 0 ? getCellBigDecimal(row.getCell(idx.moneyIn))  : null;
            BigDecimal moneyOut = idx.moneyOut >= 0 ? getCellBigDecimal(row.getCell(idx.moneyOut)) : null;

            boolean hasIn  = moneyIn  != null && moneyIn.compareTo(BigDecimal.ZERO)  > 0;
            boolean hasOut = moneyOut != null && moneyOut.compareTo(BigDecimal.ZERO) > 0;

            if (!hasIn && !hasOut) return null; // blank data row (e.g. opening balance or summary)

            // Some files put both on same row — use whichever is non-zero; if both, net them
            if (hasIn && hasOut) {
                return moneyOut.compareTo(moneyIn) >= 0
                        ? new ParsedRow(date, TransactionType.EXPENSE, moneyOut, description)
                        : new ParsedRow(date, TransactionType.INCOME,  moneyIn,  description);
            }
            if (hasOut) return new ParsedRow(date, TransactionType.EXPENSE, moneyOut, description);
            return           new ParsedRow(date, TransactionType.INCOME,  moneyIn,  description);
        }

        // ── Single amount column fallback ─────────────────────────────────────
        BigDecimal amount = idx.amount >= 0 ? getCellBigDecimal(row.getCell(idx.amount)) : null;
        if (amount == null) return null;

        String typeStr = idx.type >= 0 ? getCellString(row.getCell(idx.type)) : null;
        TransactionType type = parseTransactionType(typeStr, amount);

        if ((description == null || description.isBlank()) && typeStr != null && !isTypeKeyword(typeStr)) {
            description = typeStr;
        }

        return new ParsedRow(date, type, amount.abs(), description);
    }

    // ── CSV ──────────────────────────────────────────────────────────────────

    private List<ParsedRow> parseCsv(MultipartFile file, List<String> errors) throws IOException {
        List<ParsedRow> rows = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream()))) {
            String line;
            int lineNum = 0;
            boolean headerSkipped = false;
            while ((line = reader.readLine()) != null && lineNum <= MAX_ROWS) {
                lineNum++;
                line = line.trim();
                if (line.isEmpty()) continue;
                if (!headerSkipped) { headerSkipped = true; continue; }

                try {
                    String[] parts = splitCsvLine(line);
                    if (parts.length < 3) {
                        errors.add("Line " + lineNum + ": need at least 3 columns (Date,Type,Amount)");
                        continue;
                    }
                    LocalDate  date   = parseDate(parts[0].trim());
                    String     typeStr = parts[1].trim();
                    BigDecimal amount  = parseBigDecimal(parts[2].trim());
                    if (amount == null) {
                        errors.add("Line " + lineNum + ": invalid amount '" + parts[2].trim() + "'");
                        continue;
                    }
                    String description = parts.length > 3
                            ? parts[3].trim().replaceAll("^\"|\"$", "") : null;

                    TransactionType type = parseTransactionType(typeStr, amount);

                    if ((description == null || description.isBlank()) && !isTypeKeyword(typeStr)) {
                        description = typeStr;
                    }

                    rows.add(new ParsedRow(date, type, amount, description));
                } catch (Exception e) {
                    if (errors.size() < 20) errors.add("Line " + lineNum + ": " + e.getMessage());
                }
            }
        }
        return rows;
    }

    /** Handles quoted fields with embedded commas. */
    private String[] splitCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();
        for (char c : line.toCharArray()) {
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString());
        return fields.toArray(new String[0]);
    }

    // ── PDF ──────────────────────────────────────────────────────────────────

    private List<ParsedRow> parsePdf(MultipartFile file, List<String> errors) throws IOException {
        List<ParsedRow> rows = new ArrayList<>();
        try (PDDocument document = Loader.loadPDF(file.getBytes())) {
            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document);
            rows.addAll(parsePdfText(text, errors));
        }
        return rows;
    }

    private List<ParsedRow> parsePdfText(String text, List<String> errors) {
        List<ParsedRow> rows = new ArrayList<>();
        // Match: date  optional-description  amount (with optional sign)
        Pattern pattern = Pattern.compile(
                "(?:^|\\s)(\\d{1,2}[/.-]\\d{1,2}[/.-]\\d{2,4}|\\d{4}[/.-]\\d{2}[/.-]\\d{2})" +
                "\\s+(.{0,80}?)\\s+([-+]?\\d{1,3}(?:,\\d{3})*\\.\\d{2})\\b",
                Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(text);
        int found = 0;
        while (matcher.find() && found < MAX_ROWS) {
            try {
                String dateStr    = matcher.group(1);
                String desc       = matcher.group(2).trim();
                String amountStr  = matcher.group(3).replace(",", "");
                LocalDate  date   = parseDate(dateStr);
                BigDecimal amount = new BigDecimal(amountStr);
                TransactionType type = inferTypeFromContext(desc, amount);
                rows.add(new ParsedRow(date, type, amount.abs(), desc.isBlank() ? null : desc));
                found++;
            } catch (Exception e) {
                if (errors.size() < 20) errors.add("PDF row: " + e.getMessage());
            }
        }
        return rows;
    }

    private TransactionType inferTypeFromContext(String desc, BigDecimal amount) {
        if (amount.compareTo(BigDecimal.ZERO) < 0) return TransactionType.EXPENSE;
        String lower = desc.toLowerCase();
        if (lower.contains("debit") || lower.contains("dr ") || lower.contains("payment")
                || lower.contains("purchase") || lower.contains("withdrawal")) {
            return TransactionType.EXPENSE;
        }
        return TransactionType.INCOME;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private User getUser(Authentication authentication) {
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private LocalDate parseDateFromCell(Cell cell) {
        if (cell == null) return null;
        if (cell.getCellType() == CellType.NUMERIC && DateUtil.isCellDateFormatted(cell)) {
            return cell.getLocalDateTimeCellValue().toLocalDate();
        }
        return parseDate(getCellString(cell));
    }

    private LocalDate parseDate(String dateStr) {
        if (dateStr == null || dateStr.isBlank()) return null;
        String s = dateStr.trim();
        for (DateTimeFormatter fmt : DATE_FORMATTERS) {
            try { return LocalDate.parse(s, fmt); } catch (DateTimeParseException ignored) {}
        }
        return null;
    }

    private BigDecimal getCellBigDecimal(Cell cell) {
        if (cell == null) return null;
        if (cell.getCellType() == CellType.NUMERIC) {
            return BigDecimal.valueOf(cell.getNumericCellValue());
        }
        return parseBigDecimal(getCellString(cell));
    }

    private BigDecimal parseBigDecimal(String s) {
        if (s == null || s.isBlank()) return null;
        try { return new BigDecimal(s.replace(",", "").trim()); }
        catch (NumberFormatException e) { return null; }
    }

    private String getCellString(Cell cell) {
        if (cell == null) return null;
        return switch (cell.getCellType()) {
            case STRING  -> cell.getStringCellValue().trim();
            case NUMERIC -> {
                double v = cell.getNumericCellValue();
                yield v == Math.floor(v) ? String.valueOf((long) v) : String.valueOf(v);
            }
            case BOOLEAN -> String.valueOf(cell.getBooleanCellValue());
            default      -> null;
        };
    }

    private TransactionType parseTransactionType(String typeStr, BigDecimal amount) {
        if (typeStr == null || typeStr.isBlank()) {
            return (amount != null && amount.compareTo(BigDecimal.ZERO) < 0)
                    ? TransactionType.EXPENSE : TransactionType.INCOME;
        }
        return switch (typeStr.trim().toUpperCase()) {
            case "INCOME", "CREDIT", "CR", "IN"                           -> TransactionType.INCOME;
            case "EXPENSE", "DEBIT", "DR", "OUT", "PAYMENT", "WITHDRAWAL" -> TransactionType.EXPENSE;
            default -> (amount != null && amount.compareTo(BigDecimal.ZERO) < 0)
                    ? TransactionType.EXPENSE : TransactionType.INCOME;
        };
    }

    private boolean isTypeKeyword(String s) {
        if (s == null) return false;
        return switch (s.trim().toUpperCase()) {
            case "INCOME", "EXPENSE", "CREDIT", "DEBIT", "CR", "DR",
                    "IN", "OUT", "PAYMENT", "WITHDRAWAL" -> true;
            default -> false;
        };
    }

    private record ParsedRow(LocalDate date, TransactionType type,
                              BigDecimal amount, String description) {}
}
