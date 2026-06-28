import os
import logging
# pyrefly: ignore [missing-import]
import chromadb
from typing import Tuple
# pyrefly: ignore [missing-import]
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader, StorageContext, Settings
# pyrefly: ignore [missing-import]
from llama_index.vector_stores.chroma import ChromaVectorStore
# pyrefly: ignore [missing-import]
from llama_index.embeddings.ollama import OllamaEmbedding
# pyrefly: ignore [missing-import]
from llama_index.llms.ollama import Ollama
import config


# Set up logging
logger = logging.getLogger(__name__)

# Global variables for the index and retriever
_index = None
_retriever = None

def init_rag():
    global _index, _retriever
    try:
        # Determine paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # We store the Chroma DB in a folder within the configured database path directory
        # so that it gets persisted inside the docker volume at /data
        db_dir = os.path.dirname(config.DB_PATH) if config.DB_PATH else base_dir
        chroma_db_path = os.path.abspath(os.path.join(db_dir, "chroma_db"))
        
        logger.info(f"Initializing ChromaDB at: {chroma_db_path}")
        
        # Configure LlamaIndex settings
        ollama_url = config.OLLAMA_URL if config.OLLAMA_URL else "http://localhost:11434"
        ollama_model = config.OLLAMA_MODEL if config.OLLAMA_MODEL else "phish-gemma"
        
        Settings.llm = Ollama(
            model=ollama_model,
            request_timeout=60.0,
            base_url=ollama_url.rstrip("/")
        )
        Settings.embed_model = OllamaEmbedding(
            model_name="nomic-embed-text",
            base_url=ollama_url.rstrip("/")
        )
        
        # Create persistent Chroma client and collection
        db = chromadb.PersistentClient(path=chroma_db_path)
        chroma_collection = db.get_or_create_collection("phishing_knowledge")
        
        # Create Chroma Vector Store
        vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
        storage_context = StorageContext.from_defaults(vector_store=vector_store)
        
        # Check if collection already contains data
        collection_count = chroma_collection.count()
        logger.info(f"ChromaDB collection 'phishing_knowledge' count: {collection_count}")
        
        if collection_count > 0:
            logger.info("ChromaDB already has data. Loading index from vector store.")
            _index = VectorStoreIndex.from_vector_store(
                vector_store,
                storage_context=storage_context
            )
        else:
            logger.info("ChromaDB is empty. Loading and indexing knowledge base files.")
            input_files = [
                os.path.join(base_dir, "knowledge_base", "phishing_domains.txt"),
                os.path.join(base_dir, "knowledge_base", "legitimate_domains.txt"),
                os.path.join(base_dir, "knowledge_base", "phishing_patterns.txt")
            ]
            
            # Check files existence
            for f in input_files:
                if not os.path.exists(f):
                    logger.error(f"Required knowledge base file not found: {f}")
                    raise FileNotFoundError(f"Missing file: {f}")
            
            reader = SimpleDirectoryReader(input_files=input_files)
            documents = reader.load_data()
            
            _index = VectorStoreIndex.from_documents(
                documents,
                storage_context=storage_context
            )
            logger.info("Successfully indexed files into ChromaDB.")
            
        # Create the retriever from the index (similarity_top_k=5)
        _retriever = _index.as_retriever(similarity_top_k=5)
        
    except Exception as e:
        logger.error(f"Error during RAG initialization: {e}", exc_info=True)
        _index = None
        _retriever = None

# Perform initialization on module load
init_rag()

def retrieve_context(email_text: str) -> str:
    """Queries the index for the 5 most relevant chunks and returns them as a single combined string.
    
    Args:
        email_text: The email content or query text.
        
    Returns:
        A combined string of retrieved chunks, or empty string on failure.
    """
    global _retriever
    if not _retriever:
        logger.warning("RAG retriever not initialized. Attempting re-initialization.")
        init_rag()
        if not _retriever:
            logger.error("RAG retriever failed to initialize. Returning empty string.")
            return ""
            
    try:
        # Retrieve nodes/chunks
        nodes = _retriever.retrieve(email_text)
        if not nodes:
            return ""
            
        # Extract text content from each node and combine
        chunks = [node.node.get_content() for node in nodes]
        return "\n\n".join(chunks)
    except Exception as e:
        logger.error(f"Error retrieving context: {e}", exc_info=True)
        return ""
