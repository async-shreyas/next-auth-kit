# Contributing to next-auth-pro-kit

Thank you for considering contributing to next-auth-pro-kit! This document outlines the process for contributing to the project and helps to make the contribution process easy and effective for everyone involved.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand the expectations for all interactions within the project.

## Getting Started

1. **Fork the Repository**: Start by forking the [next-auth-pro-kit repository](https://github.com/async-shreyas/next-auth-pro-kit) on GitHub.

2. **Clone Your Fork**: Clone your fork to your local machine:
   ```bash
   git clone https://github.com/async-shreyas/next-auth-pro-kit.git
   cd next-auth-pro-kit
   ```

3. **Install Dependencies**: Install the project dependencies:
   ```bash
   npm install
   ```

4. **Set Up Development Environment**: Create a `.env.local` file based on `.env.example` with any required environment variables.

5. **Run Development Server**: Start the development server:
   ```bash
   npm run dev
   ```

## Development Workflow

### Branching Strategy

- `main` branch is the stable, production-ready code
- Development should happen on feature branches
- Name your branches with a descriptive prefix, like `feature/`, `bugfix/`, `docs/`, etc.

Example:
```bash
git checkout -b feature/add-facebook-oauth
```

### Making Changes

1. Make your changes in your feature branch
2. Write or update tests as necessary
3. Make sure all tests pass:
   ```bash
   npm run test
   ```
4. Update documentation if required

### Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for changes that don't affect code functionality
- `refactor:` for code refactoring
- `test:` for adding or modifying tests
- `chore:` for tooling changes, build process, etc.

Example:
```
feat: add Facebook OAuth provider support
```

### Pull Request Process

1. Update your fork to include the latest changes from the upstream repository:
   ```bash
   git remote add upstream https://github.com/async-shreyas/next-auth-pro-kit.git
   git fetch upstream
   git rebase upstream/main
   ```

2. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Open a pull request (PR) against the `main` branch of the original repository.

4. Ensure your PR description clearly describes the problem and solution. Include any relevant issue numbers.

5. Wait for maintainers to review your PR. Address any requested changes promptly.

## Code Style and Quality

- We use ESLint and Prettier to maintain code quality and consistency.
- Run linting before submitting PRs:
  ```bash
  npm run lint
  ```
- Format your code:
  ```bash
  npm run format
  ```

## Testing

- All new features should include appropriate tests
- Run tests to ensure your changes don't break existing functionality:
  ```bash
  npm run test
  ```

## Documentation

- Update README.md if you're changing something visible to users
- Update or add JSDoc comments for new functionality
- If adding new features, update the documentation in the `/docs` directory

## Reporting Bugs

When reporting bugs, please include:

1. A clear, descriptive title
2. Steps to reproduce the issue
3. Expected behavior
4. Actual behavior
5. Next.js version, Node.js version, and OS information
6. If possible, a minimal reproduction repository

## Feature Requests

We welcome feature requests! When suggesting a feature:

1. Describe the problem you're trying to solve
2. Explain why this feature would benefit the project
3. Provide examples of how the feature would work

## Questions?

If you have any questions about contributing, please open an issue with the label "question" or reach out to the maintainers directly.

Thank you for contributing to next-auth-pro-kit!