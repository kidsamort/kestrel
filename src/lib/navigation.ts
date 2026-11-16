import type { Category } from "../types";

export type Filter =
  | { mode: "all" }
  | { mode: "favorites" }
  | { mode: "category"; category: Category };

export type Panel = "vault" | "generator" | "settings" | "trash" | "audit";

export type Sort = "title" | "updated";

export const ALL_FILTER: Filter = { mode: "all" };

export function filterKey(filter: Filter): string {
  return filter.mode === "category" ? `category:${filter.category}` : filter.mode;
}

export function filterTitle(filter: Filter, label: string): string {
  if (filter.mode === "all") return "All items";
  if (filter.mode === "favorites") return "Favorites";
  return label;
}
