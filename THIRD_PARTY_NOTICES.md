# Third-party notices

The MIT License in this repository covers original PhishGuard software and
documentation contributed by its authors. It does not relicense third-party
datasets, upstream works, dependencies, or artifacts whose rights are held by
others.

## Documented dataset sources

Raw copies of the following training datasets are excluded from Git. PhishGuard
stores provenance manifests, aggregate evaluation evidence, and numerical model
artifacts produced through documented transformations.

### PhiUSIIL Phishing URL (Website)

- Creators: Arvind Prasad and Shalini Chandra
- Source: <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset>
- Citation: Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL
  (Website)*. UCI Machine Learning Repository.
- Associated DOI: <https://doi.org/10.1016/j.cose.2023.103545>
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Changes: PhishGuard selects URL and label fields, canonicalizes and splits
  records, derives model inputs, and publishes only aggregate evidence and
  numerical artifacts.

### PhreshPhish

- Creators: Thomas Dalton, Hemanth Gowda, Girish Rao, Sachin Pargi, Alireza
  Hadj Khodabakhshi, Joseph Rombs, Stephan Jou, and Manish Marwah
- Source: <https://huggingface.co/datasets/phreshphish/phreshphish>
- Paper: *PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing
  Website Dataset and Benchmark*, <https://arxiv.org/abs/2507.10854>
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Changes: PhishGuard pins v1.0.1, projects URL metadata rather than captured
  HTML, validates and canonicalizes records, quarantines ambiguous domains,
  creates domain-isolated partitions, and produces aggregate evidence and
  numerical candidate artifacts.

### PhishVN

- Creator: Thai Nguyen Vu
- Source: <https://data.mendeley.com/datasets/b97hxbxtpd/4>
- DOI: <https://doi.org/10.17632/b97hxbxtpd.4>
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Upstream sources named by the dataset author include NCSC Tin Nhiem Mang,
  ChongLuaDao, and Tranco.
- Changes: PhishGuard uses only eligible gold/silver training records, treats
  synthesized entries conservatively as origins, canonicalizes records,
  quarantines ambiguous domains, and produces aggregate evidence and numerical
  candidate artifacts.

CC BY 4.0 requires appropriate credit, a license link, and an indication of
changes. Nothing in this notice implies endorsement by the dataset creators.
Exact revisions, checksums, selected fields, and transformation contracts are
recorded in `ml_pipeline/dataset_manifest.json` and
`ml_pipeline/open_corpus_manifest.json`.

### Majestic Million domain reference

- Creator: Majestic-12 Ltd
- Source: <https://majestic.com/reports/majestic-million>
- Download: <https://downloads.majestic.com/majestic_million.csv>
- License: [Creative Commons Attribution 3.0 Unported](https://creativecommons.org/licenses/by/3.0/)
- Changes: PhishGuard selects the global rank and domain, normalizes domains,
  rejects invalid and duplicate entries, and retains the first 100,000 valid
  ranked domains for offline domain context.
- Reproducibility: exact retrieval time, source and output checksums, row counts,
  and transformation are in `data/reference_domains_manifest.json`.

## Removed artifacts with unresolved provenance

The following historical files predate the reproducible ML pipeline and do not
have sufficient source or redistribution records:

- `ml_models/phishguard_cnn.h5`
- `ml_models/tokenizer.json`
- `top1m.csv`

They are **not licensed under the repository's MIT License** and were removed
from the release tree. Their existence and the CNN's rejection remain visible
in Git history and `ml_models/MODEL_CARD.md`; they must not be restored or
redistributed unless the owners establish their origin and applicable terms.

## Software dependencies

Python, JavaScript, container-base, Swagger UI, and browser-platform
dependencies retain their respective upstream licenses and notices. Installing
or packaging PhishGuard does not replace those terms with the repository's MIT
License.
