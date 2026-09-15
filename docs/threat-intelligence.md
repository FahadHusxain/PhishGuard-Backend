# Threat intelligence operations

## Purpose and safety boundary

PhishGuard can match a submitted URL against a recent reviewed phishing feed.
Matching is exact after conservative URL normalization. It does not open the
destination, perform a live lookup, or extend a path-specific indicator to an
entire shared hosting domain.

The database stores only SHA-256 URL digests, source identifiers, activity
state, and snapshot metadata. Raw feed URLs must not be committed to Git. A
matching digest returns `PHISHING` with the `threat-intelligence-rules` engine.
A missing or stale feed never produces `SAFE`; normal structural analysis
continues instead.

## OpenPhish Community Feed

The free Community Feed is limited and refreshes every 12 hours. OpenPhish says
that using it accepts its Terms of Use. Those terms permit personal, academic,
or independent research but restrict commercial and organizational uses and
redistribution. Review the current terms before every deployment decision:

- https://www.openphish.com/phishing_feeds.html
- https://www.openphish.com/terms.html

For this non-commercial academic project, sync the feed explicitly:

```bash
python manage.py sync_threat_feed \
  --source openphish-community \
  --accept-openphish-terms
```

The acceptance flag is intentional. The application never downloads this feed
during a user request or automatically accepts changing third-party terms.

## Local reviewed files

An operator may import a UTF-8 text file containing one URL per line:

```bash
python manage.py sync_threat_feed \
  --source openphish-community \
  --file /secure/path/feed.txt
```

PhishTank's documented CSV feed contains verified online URLs. Use it only
after reviewing its current terms and download instructions, then import a
local file without adding the file to Git:

```bash
python manage.py sync_threat_feed \
  --source phishtank \
  --format csv \
  --file /secure/path/online-valid.csv
```

## Freshness and replacement

Each successful import is a complete snapshot for that source. Indicators not
present in the new snapshot become inactive. A source is eligible for matching
only while its snapshot is no older than
`PHISHGUARD_THREAT_FEED_MAX_AGE_HOURS`, which defaults to 36 hours. Schedule the
command outside the web process and alert on failed or stale updates.

Disable matching with `PHISHGUARD_THREAT_INTELLIGENCE_ENABLED=false` without
deleting evidence. Feed data is operational security data and must be included
in database access, backup, retention, and incident-response policy.
