# semgrep-salesforce-security-rules

Custom Semgrep rules for Salesforce Apex, Lightning Web Components (LWC), Experience Cloud, and metadata XML focused on improving AppSec, SaaS security, and CI/CD visibility across Salesforce environments.

---

# Why This Project Exists

Modern Salesforce environments are effectively cloud application platforms containing:

- custom backend logic (Apex)
- frontend applications (LWC/Aura)
- APIs
- event-driven automation
- identity & access management
- Experience Cloud/public-facing applications
- CI/CD pipelines
- large volumes of configuration metadata

However, many traditional AppSec workflows focus primarily on Apex source code while overlooking security risks introduced through:

- metadata configuration
- Experience Cloud exposure
- permission sets and profiles
- guest user access
- public Apex exposure
- configuration drift
- SaaS-specific authorization models

This project explores how Semgrep can be extended to improve Salesforce security visibility across both source code and metadata configurations using lightweight, CI/CD-friendly scanning approaches.

---

# Goals

This repository aims to:

- Improve Salesforce AppSec visibility in CI/CD workflows
- Detect high-signal Salesforce security misconfigurations
- Bridge gaps between AppSec and SaaS security tooling
- Provide open-source Semgrep rules for Salesforce ecosystems
- Experiment with metadata-aware Salesforce security scanning
- Help security and engineering teams identify risks earlier in the SDLC

---

# Current Rule Categories

## Apex Security

Examples:
- `without sharing`
- unsafe dynamic SOQL
- missing CRUD/FLS enforcement
- exposed `@AuraEnabled` methods
- insecure callouts
- hardcoded secrets/tokens

---

## Lightning Web Components (LWC)

Examples:
- unsafe DOM sinks
- insecure `innerHTML`
- unsafe `postMessage`
- hardcoded endpoints/tokens
- insecure client-side authorization assumptions

---

## Metadata XML / Configuration Security

Examples:
- dangerous profile permissions
- overly permissive guest user access
- exposed Apex class permissions
- insecure Experience Cloud configuration
- risky object/field permissions
- configuration drift indicators

---

## Experience Cloud / Guest User Security

Examples:
- public exposure risks
- guest-user-accessible Apex classes
- overly permissive guest profiles
- insecure sharing settings

---

# Example Rule

```yaml
rules:
  - id: salesforce-public-links-enabled
    pattern: |
      <enableChatterFileLink>true</enableChatterFileLink>

    message: Salesforce Public Links are enabled. Public file links can expose files externally.

    severity: ERROR

    languages:
      - generic

    paths:
      include:
        - "Content.settings-meta.xml"
```

This rule detects when Salesforce Public Links functionality is enabled at the org configuration level through metadata XML. Public Links can introduce external file-sharing and data exposure risks if not properly governed.