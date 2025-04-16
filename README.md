<p align="center">
    <h1 align="center">
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/semaphore-protocol/.github/main/assets/semaphore-logo-light.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/semaphore-protocol/.github/main/assets/semaphore-logo-dark.svg">
        <img width="250" alt="Semaphore icon" src="https://raw.githubusercontent.com/semaphore-protocol/.github/main/assets/semaphore-logo-dark.svg">
      </picture>
       <sub>Rust</sub>
    </h1>
</p>

<p align="center">
    <a href="https://github.com/semaphore-protocol" target="_blank">
        <img src="https://img.shields.io/badge/project-Semaphore-blue.svg?style=flat-square">
    </a>
    <a href="/LICENSE">
        <img alt="Github license" src="https://img.shields.io/github/license/semaphore-protocol/semaphore.svg?style=flat-square">
    </a>
    <a href="https://github.com/semaphore-protocol/semaphore/actions?query=workflow%3Aproduction">
        <img alt="GitHub Workflow test" src="https://img.shields.io/github/actions/workflow/status/semaphore-protocol/semaphore/production.yml?branch=main&label=test&style=flat-square&logo=github">
    </a>
    <a href="https://coveralls.io/github/semaphore-protocol/semaphore">
        <img alt="Coveralls" src="https://img.shields.io/coveralls/github/semaphore-protocol/semaphore?style=flat-square&logo=coveralls">
    </a>
    <a href="https://deepscan.io/dashboard#view=project&tid=16502&pid=22324&bid=657461">
        <img src="https://deepscan.io/api/teams/16502/projects/22324/branches/657461/badge/grade.svg" alt="DeepScan grade">
    </a>
    <a href="https://eslint.org/">
        <img alt="Linter eslint" src="https://img.shields.io/badge/linter-eslint-8080f2?style=flat-square&logo=eslint">
    </a>
    <a href="https://prettier.io/">
        <img alt="Code style prettier" src="https://img.shields.io/badge/code%20style-prettier-f8bc45?style=flat-square&logo=prettier">
    </a>
    <img alt="Repository top language" src="https://img.shields.io/github/languages/top/semaphore-protocol/semaphore?style=flat-square">
    <a href="https://www.gitpoap.io/gh/semaphore-protocol/semaphore" target="_blank">
        <img src="https://public-api.gitpoap.io/v1/repo/semaphore-protocol/semaphore/badge">
    </a>
    <a href="http://commitizen.github.io/cz-cli/">
        <img alt="Commitizen friendly" src="https://img.shields.io/badge/commitizen-friendly-586D76?style=flat-square">
    </a>
</p>

<div align="center">
    <h4>
        <a href="/CONTRIBUTING.md">
            👥 Contributing
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="/CODE_OF_CONDUCT.md">
            🤝 Code of conduct
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://github.com/semaphore-protocol/semaphore/contribute">
            🔎 Issues
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://semaphore.pse.dev/telegram">
            🗣️ Chat &amp; Support
        </a>
    </h4>
</div>

| Semaphore is a generic privacy layer. Leveraging zero-knowledge technology, users can prove their membership in groups and send messages (extending from votes to endorsements) off-chain or across EVM-compatible blockchains, all without revealing their personal identity. |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |

## Semaphore Rust board

All tasks related to the Semaphore Rust implementation are public. You can track their progress, statuses, and additional details in the [Semaphore Rust view](https://github.com/orgs/semaphore-protocol/projects/10/views/29).



## 🛠 Install

Clone this repository:

```bash
git clone git@github.com:semaphore-protocol/semaphore-rs.git
```

Semaphore uses `Circom-Prover` to generate zero-knowledge proofs for `Circom` circuits. Since `Circom-Prover` generates the witness function at build time, developers must specify the Merkle tree depth during compilation. This can be done by setting the `SEMAPHORE_DEPTH` environment variable:

```bash
cd semaphore-rs
SEMAPHORE_DEPTH=<tree depth> cargo build
```
