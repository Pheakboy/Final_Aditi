package groupproject.backend.service;

import groupproject.backend.model.AuditLog;

import java.util.List;

public interface AuditLogService {
    void log(String action, String performedBy, String details);
    List<AuditLog> getAll();
}
