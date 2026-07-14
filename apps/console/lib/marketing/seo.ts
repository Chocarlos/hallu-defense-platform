import type { Metadata, MetadataRoute } from "next";

import {
  getMarketingContent,
  type MarketingLocale
} from "./content";

const SOCIAL_IMAGE_PATH = "/opengraph-image";

export function buildLandingMetadata(
  locale: MarketingLocale,
  siteOrigin: string
): Metadata {
  const copy = getMarketingContent(locale);
  const canonical = absolute(siteOrigin, copy.path);
  return {
    metadataBase: new URL(siteOrigin),
    title: copy.metadata.title,
    description: copy.metadata.description,
    alternates: {
      canonical,
      languages: {
        es: absolute(siteOrigin, "/"),
        en: absolute(siteOrigin, "/en"),
        "x-default": absolute(siteOrigin, "/")
      }
    },
    openGraph: {
      type: "website",
      siteName: "Hallu Defense",
      locale: locale === "es" ? "es_ES" : "en_US",
      url: canonical,
      title: copy.metadata.title,
      description: copy.metadata.description,
      images: [{ url: SOCIAL_IMAGE_PATH, width: 1200, height: 630, alt: "Hallu Defense" }]
    },
    twitter: {
      card: "summary_large_image",
      title: copy.metadata.title,
      description: copy.metadata.description,
      images: [SOCIAL_IMAGE_PATH]
    },
    robots: { index: true, follow: true }
  };
}

export function buildPrivacyMetadata(
  locale: MarketingLocale,
  siteOrigin: string
): Metadata {
  const copy = getMarketingContent(locale);
  const path = locale === "es" ? "/privacy" : "/en/privacy";
  return {
    metadataBase: new URL(siteOrigin),
    title: `${copy.privacy.title} | Hallu Defense`,
    description: copy.privacy.intro,
    alternates: {
      canonical: absolute(siteOrigin, path),
      languages: {
        es: absolute(siteOrigin, "/privacy"),
        en: absolute(siteOrigin, "/en/privacy"),
        "x-default": absolute(siteOrigin, "/privacy")
      }
    },
    robots: { index: false, follow: true }
  };
}

export function buildMarketingSitemap(siteOrigin: string): MetadataRoute.Sitemap {
  return [
    {
      url: absolute(siteOrigin, "/"),
      changeFrequency: "monthly",
      priority: 1,
      alternates: {
        languages: {
          es: absolute(siteOrigin, "/"),
          en: absolute(siteOrigin, "/en")
        }
      }
    },
    {
      url: absolute(siteOrigin, "/en"),
      changeFrequency: "monthly",
      priority: 1,
      alternates: {
        languages: {
          es: absolute(siteOrigin, "/"),
          en: absolute(siteOrigin, "/en")
        }
      }
    }
  ];
}

export function buildMarketingRobots(siteOrigin: string): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: ["/", "/en", "/privacy", "/en/privacy"],
      disallow: ["/console", "/auth/", "/api/", "/demo-request", "/metrics"]
    },
    sitemap: absolute(siteOrigin, "/sitemap.xml")
  };
}

export function buildMarketingJsonLd(
  locale: MarketingLocale,
  siteOrigin: string
): Readonly<Record<string, unknown>> {
  const copy = getMarketingContent(locale);
  const organizationId = absolute(siteOrigin, "/#organization");
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": organizationId,
        name: "Hallu Defense",
        url: absolute(siteOrigin, copy.path)
      },
      {
        "@type": "WebApplication",
        name: "Hallu Defense",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "Web",
        url: absolute(siteOrigin, copy.path),
        description: copy.metadata.description,
        inLanguage: copy.htmlLang,
        publisher: { "@id": organizationId }
      }
    ]
  };
}

export function serializeJsonLd(value: Readonly<Record<string, unknown>>): string {
  return JSON.stringify(value).replace(/</gu, "\\u003c");
}

function absolute(siteOrigin: string, path: string): string {
  return new URL(path, `${siteOrigin}/`).toString();
}
