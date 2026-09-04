# rag_engine.py
# M2: The RAG brain.
# Retrieval + grounded generation. Embeddings AND the LLM both go through Gemini (llm.py),
# so there is no local model to download.

import os
import glob
import chromadb

from llm import call_llm, embed_texts

# Local vector database (saves itself into ./chroma_db). We supply our own Gemini
# embeddings, so Chroma never needs to download its built-in embedding model.
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="security_kb")


def ingest_knowledge(folder="knowledge"):
    """Read every .md file, split into chunks, embed them with Gemini, and store in Chroma."""
    docs, ids, metas = [], [], []
    for path in glob.glob(os.path.join(folder, "*.md")):
        source = os.path.basename(path)
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        chunks = [c.strip() for c in text.split("\n\n") if c.strip()]
        for i, chunk in enumerate(chunks):
            docs.append(chunk)
            ids.append(f"{source}-{i}")
            metas.append({"source": source})
    existing = collection.get()["ids"]
    if existing:
        collection.delete(ids=existing)  # clear old data so re-running is clean
    embeddings = embed_texts(docs)       # <-- Gemini turns each chunk into a vector
    collection.add(documents=docs, embeddings=embeddings, ids=ids, metadatas=metas)
    print(f"Ingested {len(docs)} chunks from {folder}/")


def retrieve(query, n_results=3):
    """Embed the query, find the closest chunks, return (context_text, sources)."""
    q_embedding = embed_texts([query])[0]
    results = collection.query(query_embeddings=[q_embedding], n_results=n_results)
    chunks = results["documents"][0]
    sources = [m["source"] for m in results["metadatas"][0]]
    context = "\n\n".join(f"[Source: {s}]\n{c}" for s, c in zip(sources, chunks))
    return context, sources


def ask(question, n_results=3):
    """RETRIEVE the most relevant chunks, then GENERATE an answer grounded only in them."""
    context, sources = retrieve(question, n_results)

    # GENERATE: force the LLM to answer ONLY from the retrieved context
    system = (
        "You are a security analyst assistant. Answer the question using ONLY the context provided. "
        "After each fact, cite the source file in [brackets]. "
        "If the answer is not in the context, reply exactly: 'Not in my knowledge base.'"
    )
    user = f"Context:\n{context}\n\nQuestion: {question}"
    answer = call_llm(system, user)
    return answer, sources


if __name__ == "__main__":
    ingest_knowledge()
    print("\n--- Question: What is SQL injection and how do I fix it? ---\n")
    answer, sources = ask("What is SQL injection and how do I fix it?")
    print(answer)
    print("\n(Retrieved from:", sources, ")")

    print("\n--- Off-topic question (it should REFUSE): Who won the 2018 FIFA World Cup? ---\n")
    answer2, _ = ask("Who won the 2018 FIFA World Cup?")
    print(answer2)
