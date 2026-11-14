# Makdi Changelog

## v1.1.0
- **Menu bar** — Help, Data folder (opens your crawl history and logs), check for
  Updates, and About with version and links
- **List mode** — paste any list of URLs and run full checks on exactly those
  (status, redirect chains, titles, descriptions, H1/H2, canonicals, images)
- **Include / exclude URL filters** — skip `/tag/`, `/page/`, `?replytocom` or
  limit a crawl to a section such as `/blog/`; works in all three modes
- **Sitemap generator** — build a clean `sitemap.xml` from the crawl, containing
  only indexable pages (noindex, canonicalised, redirected, blocked and error
  URLs are left out), with `lastmod` where the server reports it
- **CSV exports now include "Found On (linked from)"** — every tab's export shows
  which pages link to each URL, so broken links and redirects are fixable
  straight from the spreadsheet
- Reopening or reloading the window now restores the current crawl instead of
  showing an empty screen

## v1.0.0 — first public release
- Full crawler: 16 analysis tabs with Screaming Frog-style sub-filters
- Scored dashboard with fix suggestions, Excel & PDF export
- Crawl comparison (Changes tab), custom source search, image SEO
- URL detail panel with inlinks, outlinks and anchor text
- Internal link suggestions — unlinked mentions with ready-made anchors
- Robots.txt aware, sitemap mode, structured-data validation
