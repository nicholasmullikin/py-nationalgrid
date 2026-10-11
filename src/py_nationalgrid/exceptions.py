"""Exceptions."""

from typing import Any


class CannotConnectError(Exception):
    """Error to indicate we cannot connect."""


class InvalidAuthError(Exception):
    """Error to indicate there is invalid auth."""


class NationalGridError(Exception):
    """Base exception for National Grid API errors."""


class GraphQLError(NationalGridError):
    """Raised when GraphQL request fails."""

    def __init__(
        self,
        message: str,
        endpoint: str,
        query: str | None = None,
        variables: dict[str, Any] | None = None,
        status: int | None = None,
        response_body: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        """Initialize GraphQL error with context.

        Args:
            message: Human-readable error message
            endpoint: GraphQL endpoint URL
            query: GraphQL query that failed (optional)
            variables: Query variables (optional)
            status: HTTP status code (optional)
            response_body: Response body if available (optional)
            original_error: Original exception that caused this (optional)
        """
        super().__init__(message)
        self.endpoint = endpoint
        self.query = query
        self.variables = variables
        self.status = status
        self.response_body = response_body
        self.original_error = original_error

    def __str__(self) -> str:
        """Return a safe summary; context remains available as attributes."""
        return "GraphQLError" + (f" (HTTP {self.status})" if self.status is not None else "")


class RestAPIError(NationalGridError):
    """Raised when REST API request fails."""

    def __init__(
        self,
        message: str,
        url: str,
        method: str,
        status: int | None = None,
        response_text: str | None = None,
        original_error: Exception | None = None,
    ) -> None:
        """Initialize REST API error with context.

        Args:
            message: Human-readable error message
            url: Full request URL
            method: HTTP method (GET, POST, etc.)
            status: HTTP status code (optional)
            response_text: Response body text (optional)
            original_error: Original exception that caused this (optional)
        """
        super().__init__(message)
        self.url = url
        self.method = method
        self.status = status
        self.response_text = response_text
        self.original_error = original_error

    def __str__(self) -> str:
        """Return a safe summary; context remains available as attributes."""
        return "RestAPIError" + (f" (HTTP {self.status})" if self.status is not None else "")


class RetryExhaustedError(NationalGridError):
    """Raised when all retry attempts are exhausted."""

    def __init__(
        self,
        message: str,
        attempts: int,
        last_error: Exception,
    ) -> None:
        """Initialize retry exhausted error.

        Args:
            message: Human-readable error message
            attempts: Number of attempts made
            last_error: The final error that caused failure
        """
        super().__init__(message)
        self.attempts = attempts
        self.last_error = last_error

    def __str__(self) -> str:
        """Return a safe summary; context remains available as attributes."""
        return f"RetryExhaustedError (after {self.attempts} attempts)"


class DataExtractionError(NationalGridError):
    """Raised when expected data cannot be extracted from a response."""

    def __init__(
        self,
        message: str,
        path: str,
        response_data: Any | None = None,
    ) -> None:
        """Initialize data extraction error.

        Args:
            message: Human-readable error message
            path: The data path that could not be extracted
            response_data: The response data that was being extracted from
        """
        super().__init__(message)
        self.path = path
        self.response_data = response_data

    def __str__(self) -> str:
        """Return a safe summary; context remains available as attributes."""
        return "DataExtractionError"
