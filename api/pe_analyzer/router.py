from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from ..config import MAX_PE_FILE_SIZE_BYTES, PE_APPROVED_ROOTS
from .schemas import AnalyzeFileRequest, PEAnalysisResponse
from .service import StaticPEAnalyzer

analyzer = StaticPEAnalyzer(PE_APPROVED_ROOTS, MAX_PE_FILE_SIZE_BYTES)


class _PathSafeRoute(APIRoute):
    """Avoid echoing a caller-supplied local path in FastAPI validation errors."""

    def get_route_handler(self):
        original_handler = super().get_route_handler()

        async def route_handler(request: Request):
            try:
                return await original_handler(request)
            except RequestValidationError as error:
                details = [{
                    "loc": item.get("loc", []),
                    "msg": item.get("msg", "Invalid request."),
                    "type": item.get("type", "value_error"),
                } for item in error.errors()]
                return JSONResponse(status_code=422, content={"detail": details})

        return route_handler


router = APIRouter(route_class=_PathSafeRoute)


@router.post(
    "/api/analyze-file",
    response_model=PEAnalysisResponse,
    summary="Analyze a local Windows PE file without executing it",
)
def analyze_file(request: AnalyzeFileRequest):
    result, http_status = analyzer.analyze_path(request.path)
    return JSONResponse(status_code=http_status, content=result.model_dump(mode="json"))
