# API Documentation Testing Guide

## Manual Testing

### 1. Swagger UI Testing
1. Start your Django development server:
   ```bash
   python manage.py runserver
   ```

2. Navigate to Swagger UI:
   ```
   http://localhost:8000/swagger/
   ```

3. Test each endpoint:
   - ✅ All endpoints are listed
   - ✅ Request/response schemas are complete
   - ✅ Examples are realistic and helpful
   - ✅ Authentication works correctly
   - ✅ Error responses are documented

### 2. ReDoc Testing
1. Navigate to ReDoc:
   ```
   http://localhost:8000/redoc/
   ```

2. Verify:
   - ✅ Documentation is well-organized
   - ✅ Navigation works smoothly
   - ✅ All endpoints are accessible
   - ✅ Code examples are present

### 3. OpenAPI Schema Validation
1. Export the schema:
   ```bash
   curl http://localhost:8000/swagger.json > api_schema.json
   ```

2. Validate using online tools:
   - [Swagger Editor](https://editor.swagger.io/)
   - [OpenAPI Validator](https://apitools.dev/swagger-parser/)

## Automated Testing

### 1. Schema Validation Script
```python
import requests
import json

def test_openapi_schema():
    response = requests.get('http://localhost:8000/swagger.json')
    schema = response.json()
    
    # Basic schema validation
    assert 'openapi' in schema
    assert 'info' in schema
    assert 'paths' in schema
    
    # Check that all paths have documentation
    for path, methods in schema['paths'].items():
        for method, spec in methods.items():
            assert 'summary' in spec, f"Missing summary for {method.upper()} {path}"
            assert 'responses' in spec, f"Missing responses for {method.upper()} {path}"

test_openapi_schema()
print("✅ OpenAPI schema validation passed!")
```

### 2. Documentation Coverage Test
```python
def test_documentation_coverage():
    import os
    from pathlib import Path
    
    views_files = Path('apps').rglob('*views.py')
    undocumented = []
    
    for file_path in views_files:
        with open(file_path) as f:
            content = f.read()
            
        if '@api_view' in content or 'APIView' in content:
            if '@swagger_auto_schema' not in content:
                undocumented.append(str(file_path))
    
    if undocumented:
        print("❌ Undocumented API files:")
        for file in undocumented:
            print(f"   {file}")
    else:
        print("✅ All API files have documentation!")

test_documentation_coverage()
```

## Integration Testing

### 1. Test API Endpoints
```bash
# Test authentication
curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com", "password": "testpass123"}'

# Test with authentication token
TOKEN="your-token-here"
curl -X GET http://localhost:8000/api/deals/ \
     -H "Authorization: Token $TOKEN"
```

### 2. Validate Response Formats
Ensure API responses match the documented schemas:

```python
import requests

def test_api_response_format():
    # Login to get token
    login_response = requests.post('http://localhost:8000/api/auth/login/', {
        'email': 'test@example.com',
        'password': 'testpass123'
    })
    
    assert login_response.status_code == 200
    data = login_response.json()
    
    # Validate response structure matches documentation
    assert 'token' in data
    assert 'user' in data
    assert 'id' in data['user']
    assert 'email' in data['user']

test_api_response_format()
```

## Quality Checklist

### Documentation Quality
- [ ] All endpoints have clear, descriptive summaries
- [ ] Request/response examples are realistic
- [ ] Error cases are documented
- [ ] Authentication requirements are clear
- [ ] Rate limiting is documented
- [ ] Deprecation notices are included where applicable

### Technical Quality
- [ ] OpenAPI schema validates successfully
- [ ] Swagger UI functions without errors
- [ ] All endpoints are reachable via documentation
- [ ] Request/response schemas match actual API behavior
- [ ] Authentication flows work in documentation

### User Experience
- [ ] Documentation is easy to navigate
- [ ] Examples help users understand the API
- [ ] Error messages are helpful
- [ ] Getting started guide is available
- [ ] Integration examples are provided
