# Performance Testing Framework - Task 6.2.1

## Overview

This directory contains a comprehensive performance testing framework for the Backend_PRS application. The framework provides load testing capabilities, performance regression testing, and benchmarking suite for continuous performance monitoring.

**Task 6.2.1: Performance Test Framework ✅ COMPLETED**

## Features

### 1. Load Testing Capabilities
- **Concurrent User Simulation**: Simulate multiple users accessing the system simultaneously
- **Configurable Test Scenarios**: Customizable request patterns, think times, and ramp-up periods
- **HTTP Method Support**: GET, POST, PUT, DELETE requests with payload support
- **Authentication Support**: Bearer token authentication for protected endpoints
- **System Resource Monitoring**: Real-time CPU, memory, and I/O monitoring during tests

### 2. Performance Regression Testing
- **Baseline Establishment**: Create performance baselines for critical endpoints
- **Automated Regression Detection**: Compare current performance against established baselines
- **Configurable Tolerance**: Set acceptable performance degradation thresholds
- **Detailed Regression Reports**: Identify specific metrics that have regressed

### 3. Performance Benchmarking Suite
- **Predefined Test Scenarios**: Ready-to-use test scenarios for common API endpoints
- **Performance Metrics Collection**: Comprehensive response time, throughput, and resource usage metrics
- **Statistical Analysis**: Mean, median, percentiles, and standard deviation calculations
- **Historical Performance Tracking**: Store and compare performance results over time

## Components

### Core Framework (`performance_test_framework.py`)

The main performance testing framework that provides:

#### Classes
- `LoadTestConfig`: Configuration for load test parameters
- `PerformanceMetric`: Individual performance measurement data
- `LoadTestResult`: Comprehensive load test results
- `BenchmarkBaseline`: Performance baseline for regression testing
- `PerformanceTestFramework`: Main framework class

#### Key Methods
- `run_load_test()`: Execute load tests with concurrent users
- `establish_baseline()`: Create performance baselines for regression testing
- `run_regression_test()`: Compare current performance against baselines
- `create_api_load_test_scenarios()`: Generate predefined test scenarios

### Management Command (`backend/core/performance/management/commands/run_performance_tests.py`)

Django management command for running performance tests from command line or CI/CD pipelines.

## Usage

### Command Line Interface

#### Basic Load Test
```bash
python manage.py run_performance_tests --action=load-test --url=/api/health/ --users=10 --requests=100
```

#### Establish Baseline
```bash
python manage.py run_performance_tests --action=baseline --url=/api/deals/ --test-name=deals_listing --version=1.0.0
```

#### Run Regression Test
```bash
python manage.py run_performance_tests --action=regression --url=/api/deals/ --test-name=deals_listing --tolerance=15.0
```

#### Run Predefined Scenarios
```bash
python manage.py run_performance_tests --action=scenarios
```

#### Health Check with Performance Validation
```bash
python manage.py run_performance_tests --action=health-check
```

#### Advanced Options
```bash
# POST request with JSON payload and authentication
python manage.py run_performance_tests \
  --action=load-test \
  --url=/api/deals/ \
  --method=POST \
  --payload='{"name":"Test Deal","amount":1000}' \
  --auth-token=your-token-here \
  --users=20 \
  --requests=50 \
  --output-format=json

# Duration-based test with custom think time
python manage.py run_performance_tests \
  --action=load-test \
  --url=/api/reports/ \
  --users=15 \
  --duration=300 \
  --think-time=2.0 \
  --ramp-up=60.0
```

### Programmatic Usage

```python
from tests.performance.performance_test_framework import (
    PerformanceTestFramework, 
    LoadTestConfig
)

# Initialize framework
framework = PerformanceTestFramework("http://localhost:8000")

# Configure load test
config = LoadTestConfig(
    target_url="/api/deals/",
    concurrent_users=20,
    requests_per_user=100,
    method="GET",
    think_time=0.5,
    ramp_up_time=30.0
)

# Run load test
result = framework.run_load_test(config)

# Establish baseline
baseline = framework.establish_baseline("deals_endpoint", result, "1.0.0")

# Run regression test
regression_report = framework.run_regression_test(
    "deals_endpoint", 
    result, 
    tolerance_percent=10.0
)
```

## Test Scenarios

### Predefined Scenarios

The framework includes predefined scenarios for common endpoints:

1. **Authentication Endpoints** (`/api/auth/login/`)
   - 20 concurrent users, 50 requests each
   - POST requests with login credentials

2. **User Dashboard** (`/api/users/dashboard/`)
   - 50 concurrent users, 100 requests each
   - GET requests for dashboard data

3. **Deals Listing** (`/api/deals/`)
   - 30 concurrent users, 75 requests each
   - Organization-scoped data retrieval

4. **Commission Calculations** (`/api/commission/calculate/`)
   - 15 concurrent users, 25 requests each
   - POST requests with calculation data

5. **High-Load Scenario** (`/api/health/`)
   - 100 concurrent users, 200 requests each
   - System stress testing

6. **Database-Intensive Scenario** (`/api/reports/financial/`)
   - 10 concurrent users, 20 requests each
   - Complex query performance testing

## Metrics Collected

### Response Time Metrics
- Average response time
- Median response time
- Minimum/Maximum response times
- 95th and 99th percentile response times
- Response time distribution

### Throughput Metrics
- Requests per second (RPS)
- Total requests processed
- Successful vs failed requests
- Success rate percentage

### System Resource Metrics
- Peak memory usage (MB)
- Average CPU utilization (%)
- Disk I/O statistics
- Network I/O statistics

### Error Analysis
- HTTP status code distribution
- Error message categorization
- Failure rate analysis
- Error trend identification

## Output Formats

### Text Format (Default)
Detailed human-readable output with charts and summaries.

### JSON Format
```bash
--output-format=json
```
Machine-readable JSON output for integration with monitoring systems.

### CSV Format
```bash
--output-format=csv
```
Comma-separated values for spreadsheet analysis.

## Results Storage

### Test Results
- Location: `Backend_PRS/tests/performance/results/`
- Format: JSON files with timestamp
- Contents: Complete test results including all metrics

### Performance Baselines
- Location: `Backend_PRS/tests/performance/performance_baselines.json`
- Format: JSON database of established baselines
- Contents: Baseline metrics for regression testing

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Run Performance Tests
  run: |
    python manage.py run_performance_tests --action=health-check --quiet
    python manage.py run_performance_tests --action=regression --url=/api/deals/ --test-name=deals_listing --tolerance=20.0
```

### Docker Integration
```bash
# Run inside Docker container
docker exec backend_container python manage.py run_performance_tests --action=scenarios --quiet
```

## Performance Targets

### Response Time Targets
- **Health Endpoints**: < 100ms (95th percentile)
- **Authentication**: < 500ms (95th percentile)  
- **Data Retrieval**: < 1000ms (95th percentile)
- **Complex Reports**: < 3000ms (95th percentile)

### Throughput Targets
- **Health Endpoints**: > 1000 RPS
- **Authentication**: > 100 RPS
- **Data APIs**: > 50 RPS
- **Report Generation**: > 10 RPS

### System Resource Targets
- **Memory Usage**: < 2GB peak during testing
- **CPU Usage**: < 80% average during testing
- **Success Rate**: > 99.5% for all critical endpoints

## Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Ensure tests directory is in Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/tests"
```

#### 2. Database Connection Issues
```bash
# Check database connectivity before testing
python manage.py check --database default
```

#### 3. Memory Issues During Large Tests
```bash
# Use smaller concurrent user counts
--users=10 --requests=50
```

#### 4. Network Timeouts
```bash
# Increase timeout for slow endpoints
# Note: Timeout is configured in LoadTestConfig, default 30s
```

### Performance Investigation

#### 1. High Response Times
- Check database query performance
- Review cache hit rates
- Monitor system resource usage
- Analyze slow query logs

#### 2. Low Throughput
- Check connection pool settings
- Review middleware performance
- Monitor database connection usage
- Analyze request processing bottlenecks

#### 3. Memory Leaks
- Monitor memory usage trends
- Check for unclosed database connections
- Review cache memory usage
- Analyze object lifecycle management

## Best Practices

### 1. Test Design
- Start with small user counts and gradually increase
- Use realistic data payloads for POST/PUT requests
- Include authentication in tests for protected endpoints
- Test different user patterns (ramp-up, sustained load, spike)

### 2. Baseline Management
- Establish baselines on stable builds
- Update baselines when performance improvements are made
- Use version tags to track baseline evolution
- Document baseline establishment criteria

### 3. Regression Testing
- Set appropriate tolerance levels (typically 10-20%)
- Run regression tests on every major release
- Investigate all performance regressions before deployment
- Maintain performance regression history

### 4. Monitoring Integration
- Correlate load test results with system monitoring
- Use load tests to validate monitoring alerting
- Integrate performance testing with deployment pipelines
- Archive performance test results for trend analysis

## Future Enhancements

### Planned Improvements
- **Real User Monitoring (RUM)**: Integration with production traffic patterns
- **Multi-Environment Testing**: Support for testing against staging/production
- **Advanced Analytics**: Machine learning-based performance anomaly detection
- **Custom Scenarios**: GUI-based test scenario builder
- **Distributed Testing**: Multi-node load generation for higher concurrency

### Integration Opportunities
- **APM Integration**: Connect with Application Performance Monitoring tools
- **Alerting Integration**: Automatic alerts for performance regressions
- **Dashboard Integration**: Real-time performance testing dashboard
- **Database Integration**: Store results in time-series database for analysis

This performance testing framework provides a solid foundation for continuous performance monitoring and regression prevention in the Backend_PRS application.
