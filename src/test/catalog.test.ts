import { describe, expect, it } from "vitest";
import { CATEGORY_META, metaFor, secondaryText } from "../lib/catalog";
import type { ItemSummary } from "../types";

function summary(overrides: Partial<ItemSummary> = {}): ItemSummary {
  return {
    id: "id",
    title: "Example",
    category: "login",
    username: "",
    url: "",
    tags: [],
    favorite: false,
    hasTotp: false,
    updatedAt: 0,
    ...overrides,
  };
}

describe("metaFor", () => {
  it("resolves every category id and falls back to Logins for unknown ones", () => {
    expect(CATEGORY_META).toHaveLength(18);
    expect(new Set(CATEGORY_META.map((m) => m.id)).size).toBe(18);

    expect(metaFor("creditCard").label).toBe("Credit Cards");
    expect(metaFor("creditCard").noun).toBe("Credit Card");
    expect(metaFor("wirelessRouter").label).toBe("Routers");

    // A category the core might add later must not crash the list pane.
    expect(metaFor("madeUpCategory")).toEqual(CATEGORY_META[0]);
    expect(metaFor("")).toEqual(CATEGORY_META[0]);
  });
});

describe("secondaryText", () => {
  it("prefers the username over the URL", () => {
    expect(
      secondaryText(summary({ username: "ada", url: "https://example.com/a" })),
    ).toBe("ada");
  });

  it("falls back to the URL host, tolerating a missing scheme", () => {
    expect(secondaryText(summary({ url: "https://example.com/deep/path" }))).toBe(
      "example.com",
    );
    expect(secondaryText(summary({ url: "example.com/login" }))).toBe(
      "example.com",
    );
    expect(secondaryText(summary({ url: "not a url" }))).toBe("not a url");
  });

  it("shows the category label when there is nothing else", () => {
    expect(secondaryText(summary({ category: "passport" }))).toBe("Passports");
  });
});
