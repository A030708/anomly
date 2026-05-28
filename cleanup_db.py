#!/usr/bin/env python3
"""
Database Cleanup Script
Removes accumulated test/attack data while preserving essential seed data (users + products).

Usage:
    python cleanup_db.py              # Show what will be deleted (dry run)
    python cleanup_db.py --confirm    # Actually delete the data
    python cleanup_db.py --all        # Delete EVERYTHING including seed data
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.db_client import get_supabase

DRY_RUN = "--confirm" not in sys.argv
DELETE_ALL = "--all" in sys.argv

TABLES_TO_CLEAR = [
    "sentinel_events",
    "threat_incidents",
    "blocked_ips",
    "orders",
    "inventory_movements",
    "audit_log",
]

SEED_TABLES = ["users", "products"]


def count_rows(table):
    try:
        result = get_supabase().table(table).select("*", count="exact").limit(0).execute()
        return result.count or 0
    except Exception as e:
        return f"ERROR: {e}"


def delete_all(table):
    try:
        result = get_supabase().table(table).delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        return len(result.data)
    except Exception as e:
        return f"ERROR: {e}"


def main():
    db = get_supabase()

    print("=" * 60)
    print("  DATABASE CLEANUP TOOL")
    print("=" * 60)

    if DRY_RUN:
        print("\n  [DRY RUN] No data will be deleted.")
        print("  Run with --confirm to execute.\n")
    elif DELETE_ALL:
        print("\n  [WARNING] DELETE ALL mode -- including seed data!\n")
    else:
        print("\n  Preserving seed data (users + products).\n")

    print(f"{'Table':<25} {'Current Rows':<15} {'Action'}")
    print("-" * 55)

    for table in TABLES_TO_CLEAR:
        count = count_rows(table)
        action = "DELETE" if not DRY_RUN else "Would delete"
        print(f"  {table:<23} {str(count):<15} {action}")

    if not DELETE_ALL:
        print()
        for table in SEED_TABLES:
            count = count_rows(table)
            print(f"  {table:<23} {str(count):<15} PRESERVED")
    else:
        print()
        for table in SEED_TABLES:
            count = count_rows(table)
            print(f"  {table:<23} {str(count):<15} DELETE (--all mode)")

    print()

    if DRY_RUN:
        print("  Run: python cleanup_db.py --confirm")
        print("  To also delete seed data: python cleanup_db.py --confirm --all")
        return

    confirm = input("  Type 'yes' to confirm: ")
    if confirm != "yes":
        print("  Cancelled.")
        return

    tables_to_process = TABLES_TO_CLEAR + (SEED_TABLES if DELETE_ALL else [])

    for table in tables_to_process:
        print(f"  Deleting all rows from {table}...", end=" ")
        result = delete_all(table)
        print(f"done ({result} rows affected)")

    print("\n  Cleanup complete!")


if __name__ == "__main__":
    main()
