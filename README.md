# BugBounty: Automated Bug Bounties on GenLayer

An Intelligent Contract that lets a maintainer post a bounty against a repo issue and lets GenLayer validators decide, using an LLM, whether a contributor's pull request is merged and how severe the fixed bug is. The severity tier is agreed on by validator consensus, so no single party decides the outcome.

- **Network:** GenLayer Studio (studionet)
- **Contract address:** `0xaD495de36EA054f66e6a7fBF65aB2B36F24e76cF`
- **Contract file:** `contracts/bug_bounty.py`

## Why GenLayer

Judging a pull request is subjective and lives on the open web. A normal smart contract cannot read a GitHub page or interpret it. Here, every validator fetches the PR page itself (`gl.nondet.web.render`), asks an LLM for a structured verdict (`gl.nondet.exec_prompt`), and the network must agree on the result (`gl.eq_principle.strict_eq`) before the bounty state changes.

## How it works

1. **`create_bounty(repo_url, issue_id, amount)`** creates a bounty keyed by the creator's address. Returns an id such as `issue-42_0`.
2. **`resolve_bounty(creator, bounty_id, pr_url, contributor)`**:
   - each validator fetches the PR page and asks the LLM for `{"merged": bool, "severity": "critical|high|medium|low"}`
   - validators must return identical JSON (strict equality)
   - if the PR is merged and the severity is valid, the bounty becomes `resolved` and records the PR, severity, and contributor
3. **`cancel_bounty(bounty_id)`** lets the creator cancel an open bounty.
4. **`get_bounties()`** and **`get_bounty(creator, bounty_id)`** are read-only views.

Severity tiers map to payout percentages of the escrowed amount: critical 100%, high 70%, medium 40%, low 20%. The model's answer is normalized (lowercased, "moderate" is treated as "medium") so a reasonable synonym does not cause a revert.

## Try it

Using the GenLayer CLI (`genlayer network set studionet` first):

```
genlayer write 0xaD495de36EA054f66e6a7fBF65aB2B36F24e76cF create_bounty --args "https://github.com/vuejs/vuepress" "issue-42" 1000000

genlayer call 0xaD495de36EA054f66e6a7fBF65aB2B36F24e76cF get_bounties

genlayer write 0xaD495de36EA054f66e6a7fBF65aB2B36F24e76cF resolve_bounty --args 0x5f463B8CAC925dA573594E63adC1Bc3AA98229C8 issue-42_0 "https://github.com/vuejs/vuepress/pull/2500" 0x5f463B8CAC925dA573594E63adC1Bc3AA98229C8

genlayer call 0xaD495de36EA054f66e6a7fBF65aB2B36F24e76cF get_bounties
```

`resolve_bounty` needs a **merged** pull request on a public repo whose description makes the bug and its severity reasonably clear.

## Verified run

Bounty `issue-42_0` was created, then resolved against a merged security-fix PR (`vuejs/vuepress#2500`). Final state read back from the contract:

```
status:      resolved
severity:    medium
pr_url:      https://github.com/vuejs/vuepress/pull/2500
resolved_to: 0x5f463B8CAC925dA573594E63adC1Bc3AA98229C8
amount:      1000000
```

## Notes for the GenVM SDK

Things learned while building this that may save other builders time:

- Addresses passed through the CLI arrive as `Address` objects, not strings. Declare method parameters as `Address`, not `str`, or `Address(x)` will raise a `TypeError`.
- Use `gl.eq_principle.strict_eq(fn)` for LLM consensus and `gl.nondet.web.render(url, mode="text")` to fetch a page.
- Keep `@allow_storage @dataclass` fields to plain types (`str`, `bool`); store amounts as strings.
- Raise `Exception(...)` for validation failures.
- A contract exception still shows as `ACCEPTED` at the consensus level (validators agree it reverted). Always read state back to confirm it changed.

## Known limitations

- **No fund custody yet.** `amount` is stored as a number; no tokens are escrowed or transferred, and the payout code is left commented out until value handling is wired up.
- **No access control on `resolve_bounty`.** Any caller can currently resolve an open bounty by supplying a creator, a merged PR, and a contributor. A production version should restrict this to the creator or a designated reviewer.
- **PR-to-issue linkage is not verified.** The LLM checks that the PR is merged and estimates severity, but does not confirm that the PR actually closes the referenced issue.
- **Strict consensus.** `strict_eq` requires byte-identical JSON from all validators. In testing, validators occasionally disagreed and the majority decided. `gl.eq_principle.prompt_comparative` would tolerate near-equivalent answers.
