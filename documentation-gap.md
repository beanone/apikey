# Documentation Gaps and Inconsistencies

## Login Service Integration
- [ ] Remove or update the `LoginServiceConfig` section in README as it doesn't exist in the code
- [ ] Clarify that the current implementation uses JWT-based authentication without explicit login service configuration
- [ ] Update the configuration example to match the actual implementation

## API Endpoints
- [ ] Add details about required `service_id` in POST request
- [ ] Document response models and their fields
- [ ] Clarify authentication requirements for each endpoint

## Features
- [ ] Clarify that API key validation is handled by the `userdb` library
- [ ] Update the Features section to accurately reflect implemented functionality

## Dependencies
- [ ] Mention the dependency on the `userdb` library
- [ ] Document required database setup
- [ ] Document JWT configuration requirements

## Security
- [ ] Remove or update claims about features not implemented:
  - [ ] "API keys are scoped to the user's permissions"
  - [ ] "API key operations are logged and audited"
  - [ ] "Revoked API keys are immediately invalidated"

## Package Name
- [ ] Ensure consistency between README (`beanone-apikey`) and `pyproject.toml` (`fastapi-apikey-router`)

## Missing Documentation
- [ ] Document the `User` type and its fields
- [ ] Explain JWT token requirements
- [ ] Document the database session dependency
