# Makdi 🕷 — the free unlimited SEO crawler

**Official site & download: https://vikasdisale.com/makdi**

Makdi is a free, open-source technical SEO crawler for Windows with **no URL
limit** — a free alternative to Screaming Frog's 500-URL free version.

![Makdi dashboard](https://vikasdisale.com/wp-content/uploads/2026/07/makdi-dashboard.png)

## Features

- **16 analysis tabs** with Screaming Frog-style sub-filters — internal, external,
  security, response codes, URL, titles, descriptions, meta keywords, H1, H2,
  content, images, canonicals, page speed, custom search, changes
- **Scored dashboard (0–100)** — what's good, what needs work, every issue with a
  specific fix suggestion and the pages it affects
- **Internal link suggestions** — finds pages that mention another page's topic
  without linking to it, with the anchor text already written
- **Crawl comparison** — every crawl is saved; the Changes tab shows what broke
  and what got fixed since last time
- **List mode** — paste any list of URLs and run the full check suite on exactly those
- **Include / exclude filters** — skip `/tag/`, `/page/`, `?replytocom`, or limit a
  crawl to one section
- **Sitemap generator** — builds a clean `sitemap.xml` of indexable pages only
- **Custom source search** — search the HTML of every crawled page (find pages
  missing your analytics tag, an old brand name, a shortcode)
- **Exports** — Excel action plan, printable PDF report, and CSV on every view,
  each with the source pages that link to a broken URL
- Robots.txt aware · sitemap mode · JSON-LD validation · fully Unicode-aware
- Runs entirely on your computer — no signup, nothing sent anywhere

## Download (Windows)

Get the installer from the official site: **https://vikasdisale.com/makdi**

Makdi is new and not code-signed yet, so Windows may show
"Windows protected your PC" — click *More info → Run anyway*. That is a
new-software reputation warning, not a virus detection; the full source is here
for anyone to inspect.

## Run from source (Mac / Linux / developers)

```bash
pip install requests beautifulsoup4 lxml openpyxl
python makdi.py        # opens http://localhost:8090
```

## Build the Windows app yourself

```bash
pip install pyinstaller pywebview
pyinstaller --onedir --noconsole --name Makdi --icon makdi.ico app.py
```

Then compile `installer.iss` with [Inno Setup](https://jrsoftware.org/isinfo.php)
to produce the installer.

## License

MIT — free for personal and commercial use. Built by
[Vikas Disale](https://vikasdisale.com).

*Screaming Frog is a trademark of Screaming Frog Ltd. Makdi is an independent
project, not affiliated with or endorsed by Screaming Frog Ltd.*
