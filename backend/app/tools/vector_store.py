"""Weaviate vector store client for code similarity search."""

from typing import Any, Dict, List, Optional

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

CODE_CLASS_NAME = "CodeChunk"
FINDING_CLASS_NAME = "Finding"


class WeaviateClient:
    """Wrapper around Weaviate client for code indexing and search."""

    def __init__(self):
        self._client = None

    def _get_client(self):
        """Lazy initialization of Weaviate client."""
        if self._client is None:
            try:
                import weaviate
                from weaviate.auth import AuthApiKey

                auth = AuthApiKey(settings.WEAVIATE_API_KEY) if settings.WEAVIATE_API_KEY else None
                self._client = weaviate.connect_to_custom(
                    http_host=settings.WEAVIATE_URL.replace("http://", "").split(":")[0],
                    http_port=int(settings.WEAVIATE_URL.split(":")[-1]) if ":" in settings.WEAVIATE_URL else 8080,
                    http_secure=settings.WEAVIATE_URL.startswith("https"),
                    grpc_host=settings.WEAVIATE_URL.replace("http://", "").split(":")[0],
                    grpc_port=50051,
                    grpc_secure=False,
                    auth_credentials=auth,
                )
                self._ensure_schema()
            except Exception as exc:
                logger.error("weaviate.connect_failed", error=str(exc))
                raise
        return self._client

    def _ensure_schema(self):
        """Create Weaviate collection schema if it doesn't exist."""
        client = self._client
        try:
            if not client.collections.exists(CODE_CLASS_NAME):
                client.collections.create(
                    name=CODE_CLASS_NAME,
                    properties=[
                        {"name": "pr_id", "dataType": ["text"]},
                        {"name": "repo", "dataType": ["text"]},
                        {"name": "file_path", "dataType": ["text"]},
                        {"name": "language", "dataType": ["text"]},
                        {"name": "content", "dataType": ["text"]},
                        {"name": "chunk_index", "dataType": ["int"]},
                        {"name": "line_start", "dataType": ["int"]},
                        {"name": "line_end", "dataType": ["int"]},
                        {"name": "symbols", "dataType": ["text[]"]},
                    ],
                )
                logger.info("weaviate.schema_created", collection=CODE_CLASS_NAME)
        except Exception as exc:
            logger.warning("weaviate.schema_error", error=str(exc))

    def index_code_chunk(
        self,
        pr_id: str,
        repo: str,
        file_path: str,
        language: str,
        content: str,
        vector: List[float],
        chunk_index: int = 0,
        line_start: int = 0,
        line_end: int = 0,
        symbols: Optional[List[str]] = None,
    ) -> str:
        """Index a code chunk with its embedding vector."""
        client = self._get_client()
        collection = client.collections.get(CODE_CLASS_NAME)

        properties = {
            "pr_id": pr_id,
            "repo": repo,
            "file_path": file_path,
            "language": language,
            "content": content,
            "chunk_index": chunk_index,
            "line_start": line_start,
            "line_end": line_end,
            "symbols": symbols or [],
        }

        result = collection.data.insert(properties=properties, vector=vector)
        logger.debug("weaviate.indexed", pr_id=pr_id, file=file_path, chunk=chunk_index)
        return str(result)

    def search_similar_code(
        self,
        query_vector: List[float],
        limit: int = 5,
        filters: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Search for similar code chunks using vector similarity."""
        try:
            client = self._get_client()
            collection = client.collections.get(CODE_CLASS_NAME)

            results = collection.query.near_vector(
                near_vector=query_vector,
                limit=limit,
                return_metadata=["certainty", "distance"],
            )

            return [
                {
                    "content": obj.properties.get("content"),
                    "file_path": obj.properties.get("file_path"),
                    "repo": obj.properties.get("repo"),
                    "language": obj.properties.get("language"),
                    "line_start": obj.properties.get("line_start"),
                    "certainty": obj.metadata.certainty if obj.metadata else None,
                }
                for obj in results.objects
            ]
        except Exception as exc:
            logger.error("weaviate.search_failed", error=str(exc))
            return []

    def search_by_symbol(
        self,
        symbol: str,
        repo: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search for code containing a specific symbol (function, class, variable name)."""
        try:
            client = self._get_client()
            collection = client.collections.get(CODE_CLASS_NAME)

            from weaviate.classes.query import Filter

            filters = Filter.by_property("symbols").contains_any([symbol])
            if repo:
                filters = filters & Filter.by_property("repo").equal(repo)

            results = collection.query.fetch_objects(
                filters=filters,
                limit=limit,
            )

            return [
                {
                    "content": obj.properties.get("content"),
                    "file_path": obj.properties.get("file_path"),
                    "repo": obj.properties.get("repo"),
                    "symbol": symbol,
                }
                for obj in results.objects
            ]
        except Exception as exc:
            logger.error("weaviate.symbol_search_failed", symbol=symbol, error=str(exc))
            return []

    def hybrid_search(
        self,
        query: str,
        query_vector: List[float],
        limit: int = 5,
        alpha: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """
        Hybrid search combining BM25 keyword search and vector similarity.
        Alpha=0.0 is pure keyword, alpha=1.0 is pure vector, 0.5 is balanced.
        Uses Reciprocal Rank Fusion (RRF) internally.
        """
        try:
            client = self._get_client()
            collection = client.collections.get(CODE_CLASS_NAME)

            results = collection.query.hybrid(
                query=query,
                vector=query_vector,
                alpha=alpha,
                limit=limit,
                return_metadata=["score"],
            )

            return [
                {
                    "content": obj.properties.get("content"),
                    "file_path": obj.properties.get("file_path"),
                    "repo": obj.properties.get("repo"),
                    "language": obj.properties.get("language"),
                    "score": obj.metadata.score if obj.metadata else None,
                }
                for obj in results.objects
            ]
        except Exception as exc:
            logger.error("weaviate.hybrid_search_failed", error=str(exc))
            return []

    def delete_pr_chunks(self, pr_id: str) -> int:
        """Delete all indexed chunks for a PR."""
        try:
            client = self._get_client()
            collection = client.collections.get(CODE_CLASS_NAME)

            from weaviate.classes.query import Filter

            result = collection.data.delete_many(
                where=Filter.by_property("pr_id").equal(pr_id)
            )
            deleted = result.successful if hasattr(result, "successful") else 0
            logger.info("weaviate.deleted_pr_chunks", pr_id=pr_id, count=deleted)
            return deleted
        except Exception as exc:
            logger.error("weaviate.delete_failed", pr_id=pr_id, error=str(exc))
            return 0

    def close(self):
        """Close the Weaviate connection."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


# Singleton instance
_weaviate_client: Optional[WeaviateClient] = None


def get_vector_store() -> WeaviateClient:
    """Get or create the singleton Weaviate client."""
    global _weaviate_client
    if _weaviate_client is None:
        _weaviate_client = WeaviateClient()
    return _weaviate_client
