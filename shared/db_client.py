import os
from functools import lru_cache
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()


@lru_cache(maxsize=1)
def get_supabase():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not url:
        raise RuntimeError("SUPABASE_URL is missing")

    if not key:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is missing")

    return create_client(url, key)


def insert_row(table_name, data):
    response = get_supabase().table(table_name).insert(data).execute()
    return response.data[0] if response.data else None


def update_rows(table_name, values, column, match_value):
    response = (
        get_supabase()
        .table(table_name)
        .update(values)
        .eq(column, match_value)
        .execute()
    )
    return response.data


def select_rows(table_name, limit=100):
    response = (
        get_supabase()
        .table(table_name)
        .select("*")
        .limit(limit)
        .execute()
    )
    return response.data or []
