# Contributing

Thanks for taking a look. Issues and pull requests are welcome.

## Setup

```bash
git clone https://github.com/NizarJasim1/onyx.git && cd onyx
python -m authpath demo      # should end with "all assertions passed"
make ci                      # tests, calibration, mutation harnesses, claims gate
```

The engine has no runtime dependencies. `pip install -e ".[dev]"` adds `pytest`,
`pip install -e ".[live]"` adds `requests` for live scans.

## Ground rules

These are what keep ONYX's findings trustworthy, so PRs that break them won't be merged:

1. **No learned baselines or models in the decision path.** A verdict must come from a
   declared contract, a law that holds by definition, or a measured fact.
2. **Laws only raise candidates.** Only the confirmer can turn a candidate into a
   finding, and only with a state read-back.
3. **The calibration stays byte-identical.** If your change alters `make demo` output,
   explain why in the PR.
4. **Every number in the docs carries an evidence tier.** `make gate` checks this.
5. **Standard library only** for anything under `authpath/`.

## Adding a bug class

1. Add a law in `authpath/eil.py` (or a new module registered with the engine).
2. Add a planted bug *and* a benign decoy for it in a fixture.
3. Add a test that fires on the bug and stays silent on the decoy.
4. If the law needs a new kind of confirmation, add it to the oracle registry rather
   than special-casing the confirmer.

## Reporting a false positive

That's the most valuable issue you can open. Please include the spec (with
credentials removed), the finding report, and why you believe it's wrong.

## License of contributions

ONYX is released under the PolyForm Noncommercial License 1.0.0 and is also offered
under separate commercial licenses. By opening a pull request you agree that your
contribution is licensed under the same terms and may be included in commercially
licensed versions of ONYX.
