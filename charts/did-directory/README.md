# did-directory chart

Images are built per commit on main and tagged with the 7-character SHA
(`.github/workflows/images.yaml`). There are no release tags.

- **Dev** (`values.yaml`): after a successful `Images` run, the
  `update-dev-chart-values` workflow writes that SHA to `image.tag`.
- **Prod** (`values-prod.yaml`): `image.tag` is empty and `image.requireTag` is
  true, so rendering prod fails until the tag is set. To promote, open a PR that
  sets `image.tag` in `values-prod.yaml` to a SHA already running in dev.
