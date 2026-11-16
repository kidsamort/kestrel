import { describe, expect, it } from "vitest";
import { filterKey, filterTitle, type Filter } from "../lib/navigation";

describe("filterKey", () => {
  it("produces stable, distinct keys per filter", () => {
    expect(filterKey({ mode: "all" })).toBe("all");
    expect(filterKey({ mode: "favorites" })).toBe("favorites");
    expect(filterKey({ mode: "category", category: "creditCard" })).toBe(
      "category:creditCard",
    );
    const a: Filter = { mode: "category", category: "login" };
    const b: Filter = { mode: "category", category: "passport" };
    expect(filterKey(a)).not.toBe(filterKey(b));
  });
});

describe("filterTitle", () => {
  it("ignores the label for fixed filters and uses it for categories", () => {
    expect(filterTitle({ mode: "all" }, "Logins")).toBe("All items");
    expect(filterTitle({ mode: "favorites" }, "Logins")).toBe("Favorites");
    expect(filterTitle({ mode: "category", category: "login" }, "Logins")).toBe(
      "Logins",
    );
  });
});
