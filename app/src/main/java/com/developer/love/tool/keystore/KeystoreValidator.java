package com.developer.love.tool.keystore;

public final class KeystoreValidator {
    private KeystoreValidator() {}

    public static class ValidationResult {
        public final boolean isValid;
        public final String errorMessage;

        public ValidationResult(boolean isValid, String errorMessage) {
            this.isValid = isValid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult error(String message) {
            return new ValidationResult(false, message);
        }
    }

    public static ValidationResult validate(
            String filename,
            String keystorePassword,
            String alias,
            String keyPassword,
            String validityYearsStr,
            String commonName,
            String organization,
            String countryCode
    ) {
        if (filename == null || filename.trim().isEmpty()) {
            return ValidationResult.error("Keystore filename is required.");
        }
        if (filename.contains("/") || filename.contains("\\") || filename.contains(":")) {
            return ValidationResult.error("Filename cannot contain slashes or path characters.");
        }

        if (keystorePassword == null || keystorePassword.length() < 6) {
            return ValidationResult.error("Keystore password must be at least 6 characters.");
        }

        if (alias == null || alias.trim().isEmpty()) {
            return ValidationResult.error("Key alias is required.");
        }

        if (keyPassword == null || keyPassword.length() < 6) {
            return ValidationResult.error("Key password must be at least 6 characters.");
        }

        int validityYears;
        try {
            validityYears = Integer.parseInt(validityYearsStr != null ? validityYearsStr.trim() : "0");
            if (validityYears <= 0 || validityYears > 1000) {
                return ValidationResult.error("Validity must be between 1 and 1000 years.");
            }
        } catch (NumberFormatException e) {
            return ValidationResult.error("Validity must be a valid positive number of years.");
        }

        if (commonName == null || commonName.trim().isEmpty()) {
            return ValidationResult.error("Certificate Name (CN) is required.");
        }

        if (organization == null || organization.trim().isEmpty()) {
            return ValidationResult.error("Organization (O) is required.");
        }

        if (countryCode != null && !countryCode.trim().isEmpty()) {
            String cc = countryCode.trim();
            if (cc.length() != 2) {
                return ValidationResult.error("Country code must be exactly 2 letters (e.g. IN, US, GB).");
            }
        }

        return ValidationResult.success();
    }
}
