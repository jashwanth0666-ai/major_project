package com.aiwatchdog.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AnalyzeRequest(

        @NotBlank(message = "URL must not be empty") @Size(max = 4096, message = "URL must not exceed 4096 characters") String url

) {
}