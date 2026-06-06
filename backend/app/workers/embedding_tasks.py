"""Celery tasks for code embedding and vector store indexing."""

import asyncio
from typing import Any, Dict, List

import structlog

from app.workers.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.workers.embedding_tasks.embed_pr_diff",
    queue="embeddings",
    max_retries=2,
)
def embed_pr_diff(pr_id: str, diff_content: str) -> Dict[str, Any]:
    """
    Embed a PR diff and index chunks into the vector store.
    Called after a PR review completes.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_embed_pr_diff_async(pr_id, diff_content))
    finally:
        loop.close()


async def _embed_pr_diff_async(pr_id: str, diff_content: str) -> Dict[str, Any]:
    """Async implementation of diff embedding."""
    from app.tools.code_analysis import chunk_diff_by_file, chunk_code_for_embedding, extract_code_from_diff

    log = logger.bind(pr_id=pr_id)
    log.info("embedding.start")

    file_chunks = chunk_diff_by_file(diff_content)
    total_indexed = 0

    for file_chunk in file_chunks[:20]:  # Limit files per PR
        code = extract_code_from_diff(file_chunk["diff_chunk"])
        if not code.strip() or len(code) < 50:
            continue

        code_chunks = chunk_code_for_embedding(
            code=code,
            file_path=file_chunk["file_path"],
            chunk_size=50,
            overlap=10,
        )

        for chunk in code_chunks[:10]:  # Limit chunks per file
            # Generate a simple embedding using hash-based approach
            # In production, use OpenAI/Anthropic embeddings
            vector = _generate_mock_embedding(chunk["content"])

            try:
                from app.tools.vector_store import get_vector_store
                vs = get_vector_store()
                vs.index_code_chunk(
                    pr_id=pr_id,
                    repo="unknown",  # Would be passed in from PR data
                    file_path=file_chunk["file_path"],
                    language=file_chunk["language"],
                    content=chunk["content"],
                    vector=vector,
                    chunk_index=chunk["chunk_index"],
                    line_start=chunk["line_start"],
                    line_end=chunk["line_end"],
                    symbols=chunk["symbols"],
                )
                total_indexed += 1
            except Exception as exc:
                log.warning("embedding.index_failed", error=str(exc))

    log.info("embedding.complete", chunks_indexed=total_indexed)
    return {"pr_id": pr_id, "chunks_indexed": total_indexed}


def _generate_mock_embedding(text: str, dimensions: int = 768) -> List[float]:
    """
    Generate a deterministic mock embedding for testing.
    In production, replace with real embeddings from OpenAI/Anthropic.
    """
    import hashlib
    import struct

    # Hash-based pseudo-embedding (deterministic, not semantic)
    hash_bytes = hashlib.sha256(text.encode()).digest()
    vector = []
    for i in range(dimensions):
        byte_idx = i % len(hash_bytes)
        shift = (i // len(hash_bytes)) % 8
        value = ((hash_bytes[byte_idx] >> shift) & 0xFF) / 255.0 - 0.5
        vector.append(value)

    # Normalize
    magnitude = sum(v * v for v in vector) ** 0.5
    if magnitude > 0:
        vector = [v / magnitude for v in vector]

    return vector


@celery_app.task(
    name="app.workers.embedding_tasks.reembed_all_prs",
    queue="embeddings",
)
def reembed_all_prs() -> Dict[str, Any]:
    """
    Nightly Celery beat task to re-embed all PRs.
    Useful after upgrading embedding models.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_reembed_all_async())
    finally:
        loop.close()


async def _reembed_all_async() -> Dict[str, Any]:
    """Re-embed all completed PRs."""
    from sqlalchemy import select

    from app.database import async_session_factory
    from app.models.pr import PRStatus, PullRequest

    logger.info("reembedding.start")
    processed = 0

    async with async_session_factory() as session:
        result = await session.execute(
            select(PullRequest)
            .where(PullRequest.status == PRStatus.COMPLETED.value)
            .limit(100)  # Process 100 PRs per run
        )
        prs = result.scalars().all()

        for pr in prs:
            try:
                # Queue individual embedding tasks
                embed_pr_diff.delay(str(pr.id), "")  # Diff would be fetched
                processed += 1
            except Exception as exc:
                logger.warning("reembedding.pr_failed", pr_id=str(pr.id), error=str(exc))

    logger.info("reembedding.complete", processed=processed)
    return {"processed": processed}
