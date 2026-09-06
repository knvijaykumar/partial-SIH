import os
from typing import Optional
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

_supabase_client: Optional[Client] = None


def get_supabase_client() -> Client:
    """
    Initializes and returns a singleton Supabase client instance.
    Validates required environment variables and raises descriptive errors if missing.
    """
    global _supabase_client

    if _supabase_client is not None:
        return _supabase_client

    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = (
        os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
        or os.getenv("SUPABASE_PUBLISHABLE_KEY")
        or os.getenv("publishable key")
    )

    if not supabase_url:
        raise RuntimeError(
            "SUPABASE_URL environment variable is missing. Please configure it in .env"
        )

    if not supabase_key:
        raise RuntimeError(
            "SUPABASE_KEY environment variable is missing. Please configure it in .env"
        )

    try:
        _supabase_client = create_client(supabase_url.strip(), supabase_key.strip())
        return _supabase_client
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Supabase client: {str(e)}") from e


def init_supabase() -> Client:
    return get_supabase_client()
