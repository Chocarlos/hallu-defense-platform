import { describe, expect, it } from "vitest";

import {
  buildLandingMetadata,
  buildMarketingJsonLd,
  buildMarketingRobots,
  buildMarketingSitemap,
  buildPrivacyMetadata,
  serializeJsonLd
} from "./seo";

const ORIGIN = "https://hallu.example";

describe("marketing SEO", () => {
  it("publishes canonical and hreflang metadata for both landing pages", () => {
    const es = buildLandingMetadata("es", ORIGIN);
    const en = buildLandingMetadata("en", ORIGIN);

    expect(es.alternates?.canonical).toBe(`${ORIGIN}/`);
    expect(en.alternates?.canonical).toBe(`${ORIGIN}/en`);
    expect(es.alternates?.languages).toEqual({
      es: `${ORIGIN}/`,
      en: `${ORIGIN}/en`,
      "x-default": `${ORIGIN}/`
    });
    expect(en.openGraph?.locale).toBe("en_US");
  });

  it("keeps privacy pages discoverable by links but out of the search index", () => {
    const metadata = buildPrivacyMetadata("en", ORIGIN);
    expect(metadata.alternates?.canonical).toBe(`${ORIGIN}/en/privacy`);
    expect(metadata.robots).toEqual({ index: false, follow: true });
  });

  it("limits the sitemap to the two public landing pages", () => {
    const sitemap = buildMarketingSitemap(ORIGIN);
    expect(sitemap.map(({ url }) => url)).toEqual([`${ORIGIN}/`, `${ORIGIN}/en`]);
  });

  it("allows public routes and blocks operational surfaces in robots", () => {
    const robots = buildMarketingRobots(ORIGIN);
    expect(robots.rules).toEqual({
      userAgent: "*",
      allow: ["/", "/en", "/privacy", "/en/privacy"],
      disallow: ["/console", "/auth/", "/api/", "/demo-request", "/metrics"]
    });
    expect(robots.sitemap).toBe(`${ORIGIN}/sitemap.xml`);
  });

  it("emits honest, script-safe structured data", () => {
    const jsonLd = buildMarketingJsonLd("es", ORIGIN);
    const serialized = serializeJsonLd({ ...jsonLd, probe: "</script>" });

    expect(serialized).not.toContain("</script>");
    expect(serialized).not.toMatch(/offers|aggregateRating|price/iu);
    expect(JSON.parse(serialized)).toMatchObject({
      "@context": "https://schema.org",
      probe: "</script>"
    });
  });
});
