from __future__ import annotations

import hashlib
import logging
import math
import os
import stat
from pathlib import Path
from typing import Iterable

import pefile

from .schemas import (
    AnalysisError,
    ImportIndicators,
    PEAnalysisResponse,
    SectionIndicators,
)
from .scoring import BASELINE, WEIGHTS, score_indicators

logger = logging.getLogger(__name__)

MAX_SECTIONS_RETURNED = 96
MAX_IMPORT_DLLS_RETURNED = 128
MAX_APIS_PER_DLL_RETURNED = 1024
MAX_TOTAL_APIS_RETURNED = 4096
MAX_NAME_LENGTH = 256
HIGH_ENTROPY_THRESHOLD = 7.2
MIN_SECTION_BYTES_FOR_ENTROPY = 1024

SENSITIVE_API_NAMES = frozenset({
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "ntwritevirtualmemory",
    "createremotethread",
    "createremotethreadex",
    "ntcreatethreadex",
    "queueuserapc",
    "setthreadcontext",
})

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class _AnalysisFailure(Exception):
    def __init__(self, status: str, code: str, message: str, http_status: int):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.http_status = http_status


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def detect_sensitive_imports(api_names: Iterable[str]) -> list[str]:
    """Return each selected sensitive import once, preserving its original spelling."""
    found: dict[str, str] = {}
    for name in api_names:
        normalized = name.casefold()
        if normalized in SENSITIVE_API_NAMES:
            found.setdefault(normalized, name[:MAX_NAME_LENGTH])
    return [found[name] for name in sorted(found)]


class StaticPEAnalyzer:
    """Parses bounded PE bytes and never loads or executes the analyzed file."""

    def __init__(self, approved_roots: Iterable[Path], max_file_size_bytes: int):
        if max_file_size_bytes < 1:
            raise ValueError("max_file_size_bytes must be positive")
        self.max_file_size_bytes = max_file_size_bytes
        self.approved_roots = tuple(Path(root).expanduser() for root in approved_roots)

    def analyze_path(self, requested_path: str) -> tuple[PEAnalysisResponse, int]:
        file_name = self._safe_file_name(requested_path)
        try:
            path = self._validate_path(requested_path)
            file_name = self._safe_file_name(path.name)
            if path.suffix.casefold() not in {".exe", ".dll"}:
                raise _AnalysisFailure(
                    "UNSUPPORTED_FILE", "UNSUPPORTED_EXTENSION",
                    "Only .exe and .dll files are supported.", 415,
                )
            data, file_size, digest = self._read_stable_file(path)
        except _AnalysisFailure as failure:
            result = PEAnalysisResponse(
                status=failure.status,
                file_name=file_name,
                error=AnalysisError(code=failure.code, message=failure.message),
            )
            self._log_result(result)
            return result, failure.http_status

        try:
            pe = pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError:
            result = PEAnalysisResponse(
                status="INVALID_PE", file_name=file_name, sha256=digest,
                file_size_bytes=file_size, pe_valid=False,
                error=AnalysisError(code="INVALID_PE", message="The file is not a valid or complete PE image."),
            )
            self._log_result(result)
            return result, 200
        except Exception as exc:
            logger.warning("PE parsing failed: file=%s category=%s", file_name, type(exc).__name__)
            result = PEAnalysisResponse(
                status="ANALYSIS_ERROR", file_name=file_name, sha256=digest,
                file_size_bytes=file_size, pe_valid=None,
                error=AnalysisError(code="PARSER_ERROR", message="The PE parser could not analyze this file safely."),
            )
            self._log_result(result)
            return result, 500

        try:
            result = self._extract_indicators(pe, data, file_name, file_size, digest)
        except Exception as exc:
            logger.warning("PE indicator extraction failed: file=%s category=%s", file_name, type(exc).__name__)
            result = PEAnalysisResponse(
                status="ANALYSIS_ERROR", file_name=file_name, sha256=digest,
                file_size_bytes=file_size, pe_valid=True,
                error=AnalysisError(code="ANALYSIS_ERROR", message="PE indicators could not be extracted safely."),
            )
            self._log_result(result)
            return result, 500
        self._log_result(result)
        return result, 200

    @staticmethod
    def _safe_file_name(value: str) -> str | None:
        try:
            name = Path(value).name
            safe_name = "".join(character for character in name if character.isprintable())
            return safe_name[:MAX_NAME_LENGTH] if safe_name else None
        except (TypeError, ValueError):
            return None

    def _validate_path(self, supplied: str) -> Path:
        if not self.approved_roots:
            raise _AnalysisFailure(
                "REJECTED_PATH", "NO_APPROVED_ROOTS",
                "PE analysis is unavailable until approved local roots are configured.", 403,
            )
        try:
            supplied_path = Path(supplied).expanduser()
            if not supplied_path.is_absolute() or ".." in supplied_path.parts:
                raise _AnalysisFailure(
                    "REJECTED_PATH", "PATH_NOT_ALLOWED",
                    "The path must be absolute and must not contain traversal components.", 403,
                )
            resolved = supplied_path.resolve(strict=True)
            if not resolved.is_file():
                raise _AnalysisFailure(
                    "ANALYSIS_ERROR", "FILE_UNAVAILABLE", "The selected file is unavailable.", 404,
                )
            roots = []
            for root in self.approved_roots:
                try:
                    canonical_root = root.resolve(strict=True)
                    if canonical_root.is_dir():
                        roots.append(canonical_root)
                except (OSError, RuntimeError):
                    continue
            if not any(self._is_relative_to(resolved, root) for root in roots):
                raise _AnalysisFailure(
                    "REJECTED_PATH", "PATH_NOT_ALLOWED",
                    "The selected file is outside configured PE analysis roots.", 403,
                )
            return resolved
        except _AnalysisFailure:
            raise
        except FileNotFoundError as exc:
            raise _AnalysisFailure(
                "ANALYSIS_ERROR", "FILE_UNAVAILABLE", "The selected file is unavailable.", 404,
            ) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise _AnalysisFailure(
                "ANALYSIS_ERROR", "PATH_UNAVAILABLE", "The selected file path could not be accessed.", 403,
            ) from exc

    @staticmethod
    def _is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _read_stable_file(self, path: Path) -> tuple[bytes, int, str]:
        try:
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise _AnalysisFailure(
                        "ANALYSIS_ERROR", "FILE_UNAVAILABLE", "The selected file is unavailable.", 404,
                    )
                if before.st_size > self.max_file_size_bytes:
                    raise _AnalysisFailure(
                        "REJECTED_PATH", "FILE_TOO_LARGE",
                        "The selected file exceeds the configured size limit.", 413,
                    )
                data = stream.read(self.max_file_size_bytes + 1)
                after = os.fstat(stream.fileno())
            if len(data) > self.max_file_size_bytes:
                raise _AnalysisFailure(
                    "REJECTED_PATH", "FILE_TOO_LARGE",
                    "The selected file exceeds the configured size limit.", 413,
                )
            if self._changed_during_read(before, after) or len(data) != after.st_size:
                raise _AnalysisFailure(
                    "ANALYSIS_ERROR", "FILE_CHANGED",
                    "The file changed during analysis; retry after it is stable.", 409,
                )
            return data, len(data), hashlib.sha256(data).hexdigest()
        except _AnalysisFailure:
            raise
        except (OSError, PermissionError) as exc:
            raise _AnalysisFailure(
                "ANALYSIS_ERROR", "FILE_UNAVAILABLE", "The selected file could not be read.", 403,
            ) from exc

    @staticmethod
    def _changed_during_read(before: os.stat_result, after: os.stat_result) -> bool:
        return any((
            before.st_size != after.st_size,
            before.st_mtime_ns != after.st_mtime_ns,
            before.st_ino != after.st_ino,
            before.st_dev != after.st_dev,
        ))

    def _extract_indicators(
        self, pe: pefile.PE, data: bytes, file_name: str, file_size: int, digest: str,
    ) -> PEAnalysisResponse:
        anomalies: list[str] = []
        sections: list[SectionIndicators] = []
        all_sections = list(pe.sections or [])
        header_section_count = getattr(pe.FILE_HEADER, "NumberOfSections", len(all_sections))
        if header_section_count != len(all_sections):
            anomalies.append("SECTION_COUNT_MISMATCH")
        if not all_sections:
            anomalies.append("NO_SECTIONS")

        raw_ranges: list[tuple[int, int]] = []
        writable_executable = False
        high_entropy_section = False
        for section in all_sections[:MAX_SECTIONS_RETURNED]:
            name = self._decode_name(section.Name)
            raw_size = int(section.SizeOfRawData)
            raw_start = int(section.PointerToRawData)
            raw_end = raw_start + raw_size
            if raw_size and (raw_start > file_size or raw_end > file_size):
                anomalies.append("SECTION_RAW_DATA_OUT_OF_BOUNDS")
            elif raw_size:
                raw_ranges.append((raw_start, raw_end))
            characteristics = int(section.Characteristics)
            readable = bool(characteristics & IMAGE_SCN_MEM_READ)
            writable = bool(characteristics & IMAGE_SCN_MEM_WRITE)
            executable = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
            writable_executable |= writable and executable
            entropy = None
            try:
                raw = section.get_data() if raw_size else b""
                entropy = shannon_entropy(raw)
                high_entropy_section |= len(raw) >= MIN_SECTION_BYTES_FOR_ENTROPY and entropy >= HIGH_ENTROPY_THRESHOLD
            except (ValueError, pefile.PEFormatError):
                anomalies.append("SECTION_DATA_UNREADABLE")
            sections.append(SectionIndicators(
                name=name,
                virtual_size=int(section.Misc_VirtualSize),
                raw_size=raw_size,
                entropy=round(entropy, 4) if entropy is not None else None,
                readable=readable,
                writable=writable,
                executable=executable,
                characteristics=characteristics,
            ))

        previous_end = -1
        for start, end in sorted(raw_ranges):
            if start < previous_end:
                anomalies.append("SECTION_RAW_RANGES_OVERLAP")
                break
            previous_end = end

        entry_point_anomaly = self._entry_point_anomaly(pe, all_sections)
        if entry_point_anomaly:
            anomalies.append("ENTRY_POINT_OUTSIDE_EXECUTABLE_SECTION")

        imports, sensitive_imports, import_anomaly = self._extract_imports(pe)
        if import_anomaly:
            anomalies.append(import_anomaly)

        unique_anomalies = list(dict.fromkeys(anomalies))
        boundary_anomaly = any(value in unique_anomalies for value in (
            "SECTION_RAW_DATA_OUT_OF_BOUNDS", "SECTION_RAW_RANGES_OVERLAP", "IMPORT_TABLE_MALFORMED",
        ))
        score = score_indicators(
            writable_executable_section=writable_executable,
            high_entropy_section=high_entropy_section,
            sensitive_imports=bool(sensitive_imports),
            file_boundary_anomaly=boundary_anomaly,
            entry_point_anomaly=entry_point_anomaly,
        )
        descriptions = []
        if writable_executable:
            descriptions.append(f"At least one section is writable and executable (+{WEIGHTS['writable_executable_section']}).")
        if high_entropy_section:
            descriptions.append(f"At least one section has entropy at or above {HIGH_ENTROPY_THRESHOLD:.1f} bits per byte (+{WEIGHTS['high_entropy_section']}); this may also occur in legitimate compressed software.")
        if sensitive_imports:
            descriptions.append(f"Selected sensitive Windows APIs are imported (+{WEIGHTS['sensitive_imports']}); their presence alone does not indicate malware.")
        if boundary_anomaly:
            descriptions.append(f"One or more file-boundary or table anomalies were detected (+{WEIGHTS['file_boundary_anomaly']}).")
        if entry_point_anomaly:
            descriptions.append(f"The entry point does not map to an executable section (+{WEIGHTS['entry_point_anomaly']}).")
        if not descriptions:
            descriptions.append("No configured suspicious structural indicators were detected; this does not establish that the file is clean.")

        machine = int(getattr(pe.FILE_HEADER, "Machine", 0))
        return PEAnalysisResponse(
            status="ANALYZED",
            file_name=file_name,
            sha256=digest,
            file_size_bytes=file_size,
            pe_valid=True,
            architecture=MACHINE_NAMES.get(machine, f"unknown (0x{machine:04x})"),
            section_count=len(all_sections),
            sections=sections,
            imports=imports,
            sensitive_imports=sensitive_imports,
            anomalies=unique_anomalies,
            suspicious_indicators=descriptions,
            risk_score=score,
            risk_score_explanation=(
                f"Heuristic, not a calibrated probability of malware. Starts at {BASELINE}; adds once per independent evidence group: "
                f"writable+executable section {WEIGHTS['writable_executable_section']}, high entropy section {WEIGHTS['high_entropy_section']}, "
                f"selected sensitive imports {WEIGHTS['sensitive_imports']}, file-boundary/table anomaly {WEIGHTS['file_boundary_anomaly']}, "
                f"entry-point anomaly {WEIGHTS['entry_point_anomaly']}; clamped to 0–100."
            ),
        )

    @staticmethod
    def _decode_name(value: bytes) -> str:
        return value.split(b"\0", 1)[0].decode("ascii", errors="replace")[:MAX_NAME_LENGTH]

    @staticmethod
    def _entry_point_anomaly(pe: pefile.PE, sections: list) -> bool:
        entry_point = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
        if entry_point == 0:
            return False
        for section in sections:
            start = int(section.VirtualAddress)
            end = start + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if start <= entry_point < end:
                return not bool(int(section.Characteristics) & IMAGE_SCN_MEM_EXECUTE)
        return True

    @staticmethod
    def _extract_imports(pe: pefile.PE) -> tuple[list[ImportIndicators], list[str], str | None]:
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except pefile.PEFormatError:
            return [], [], "IMPORT_TABLE_MALFORMED"
        entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
        groups: list[ImportIndicators] = []
        api_names: list[str] = []
        total = 0
        for entry in entries[:MAX_IMPORT_DLLS_RETURNED]:
            dll = StaticPEAnalyzer._decode_import_name(entry.dll)
            apis = []
            for imported in entry.imports[:MAX_APIS_PER_DLL_RETURNED]:
                if total >= MAX_TOTAL_APIS_RETURNED:
                    break
                name = StaticPEAnalyzer._decode_import_name(imported.name)
                if name:
                    apis.append(name)
                    api_names.append(name)
                    total += 1
            groups.append(ImportIndicators(dll=dll, apis=apis))
            if total >= MAX_TOTAL_APIS_RETURNED:
                break
        return groups, detect_sensitive_imports(api_names), None

    @staticmethod
    def _decode_import_name(value: bytes | None) -> str:
        if not value:
            return ""
        return value.decode("ascii", errors="replace")[:MAX_NAME_LENGTH]

    @staticmethod
    def _log_result(result: PEAnalysisResponse) -> None:
        logger.info(
            "Static PE analysis finished: file=%s status=%s score=%s sha256=%s",
            result.file_name or "[unknown]", result.status, result.risk_score, result.sha256,
        )
