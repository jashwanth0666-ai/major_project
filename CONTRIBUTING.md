# Contributing Guide

Welcome! This repository follows an **industry-style team workflow** for a final year major project.

Please read and follow this guide before contributing.

---

## 1) Team Workflow Overview

We use:
- Feature branches
- Pull Requests (PRs)
- Peer reviews
- Issue-based planning
- CI checks before merge

No direct commits to `main`.

---

## 2) Branching Rules

### Protected branches
- `main`: stable, release-ready code only
- `develop`: integration branch for tested features

### Working branches
Create branches from `develop` using:
- `feature/<short-name>` for new features
- `bugfix/<short-name>` for bug fixes
- `docs/<short-name>` for documentation updates

Examples:
- `feature/react-dashboard`
- `feature/spring-auth-jwt`
- `feature/fastapi-ml-predict`
- `bugfix/jwt-refresh-error`

---

## 3) Task Flow (Industry Style)

1. Create/select an issue.
2. Assign issue owner.
3. Create branch from `develop`.
4. Implement and commit changes.
5. Push branch and open PR to `develop`.
6. Get at least 1 teammate review.
7. Fix review comments.
8. Ensure CI passes.
9. Merge PR.

---

## 4) Commit Message Convention

Use conventional commit prefixes:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `refactor:` code improvement without behavior change
- `test:` add/update tests
- `chore:` tooling/config updates

Examples:
- `feat: add URL scan endpoint in spring service`
- `fix: handle null whois response in ml service`
- `docs: update setup steps for docker`

---

## 5) Pull Request Guidelines

Each PR should:
- Be focused on one logical task.
- Include clear summary of changes.
- Reference the related issue (e.g., `Closes #12`).
- Include testing notes.
- Include screenshots for UI changes.

### PR checklist
- [ ] Branch is up to date with `develop`
- [ ] Code compiles and runs locally
- [ ] Tests added/updated (if applicable)
- [ ] No secrets/keys committed
- [ ] Documentation updated (if needed)

---

## 6) Code Review Expectations

Reviewers should check:
- Correctness and edge cases
- Security and input validation
- Readability and maintainability
- API contract compatibility
- Test coverage impact

Review tone must remain professional and constructive.

---

## 7) Coding Standards

### Java (Spring Boot)
- Follow clean layered architecture (controller/service/repository).
- Validate all request DTOs.
- Use centralized exception handling.
- Keep business logic out of controllers.

### Python (FastAPI / ML)
- Keep inference endpoints stateless where possible.
- Separate training, feature extraction, and inference modules.
- Log inference failures with actionable context.

### React (TypeScript)
- Use typed props and API models.
- Keep components reusable and small.
- Handle loading/error/empty states explicitly.

---

## 8) Security & Secrets

- Never commit API keys, tokens, passwords, or `.env` files.
- Use `.env.example` for required config keys.
- Rotate any accidentally exposed key immediately.
- Prefer server-side validation for all critical operations.

---

## 9) Testing Expectations

Minimum before merge:
- Relevant unit tests for changed logic.
- Manual API validation for backend endpoints.
- UI sanity checks for frontend changes.

Suggested tools:
- Java: JUnit
- Python: pytest
- API: Postman/cURL

---

## 10) Communication Protocol

- Use issues for task planning.
- Use PR comments for technical feedback.
- Keep progress updates concise and regular.
- Escalate blockers early to project lead.

---

## 11) First-Time Contributor Setup

1. Fork (optional for outside collaborators) or clone repo.
2. Create local branch from `develop`.
3. Set up backend/frontend/python environments.
4. Run project locally.
5. Pick assigned issue and start implementation.

---

## 12) Definition of Done

A contribution is considered done only when:
- Code is merged via PR.
- Review comments are resolved.
- CI checks pass.
- Required tests are completed.
- Documentation is updated.

---

Thanks for contributing and helping the team work like a real product engineering team 🚀
