# API Documentation Checklist

Use this checklist to ensure comprehensive API documentation:

## ✅ For Each Endpoint

### Basic Documentation
- [ ] `@swagger_auto_schema` decorator applied
- [ ] Clear `operation_summary` (max 50 characters)  
- [ ] Detailed `operation_description` with examples
- [ ] Appropriate `tags` for grouping
- [ ] All HTTP methods documented

### Request Documentation
- [ ] Request body schema defined (for POST/PUT/PATCH)
- [ ] All required fields marked as required
- [ ] Field descriptions with examples
- [ ] Validation rules documented
- [ ] File upload endpoints have multipart/form-data

### Response Documentation  
- [ ] All possible response codes documented
- [ ] Success response schemas defined
- [ ] Error response schemas included
- [ ] Response examples provided
- [ ] Pagination schema for list endpoints

### Security Documentation
- [ ] Authentication requirements specified
- [ ] Permission classes documented
- [ ] Rate limiting information included
- [ ] Security considerations noted

### Additional Documentation
- [ ] Query parameters documented
- [ ] Path parameters documented  
- [ ] Filtering options explained
- [ ] Ordering options explained
- [ ] Search functionality documented

## ✅ For Each Module

### Module-Level Documentation
- [ ] Module overview in docstring
- [ ] Key endpoints listed
- [ ] Business logic explained
- [ ] Data relationships documented

### Integration Documentation
- [ ] Usage examples provided
- [ ] SDK examples for popular languages
- [ ] Error handling examples
- [ ] Authentication flow examples

## ✅ Overall API Documentation

### OpenAPI Schema
- [ ] API info complete (title, description, version)
- [ ] Server URLs configured
- [ ] Security schemes defined
- [ ] Contact information provided
- [ ] License information included

### Interactive Documentation
- [ ] Swagger UI accessible and functional
- [ ] ReDoc available as alternative
- [ ] Try-it-out functionality works
- [ ] Examples execute successfully

### Integration Guides
- [ ] Getting started guide
- [ ] Authentication guide  
- [ ] Error handling guide
- [ ] Rate limiting guide
- [ ] SDK and code examples

### Maintenance
- [ ] Documentation CI/CD pipeline
- [ ] Automated documentation testing
- [ ] Version management strategy
- [ ] Deprecation notices for old endpoints
