"""
Comprehensive SQL Injection Testing Framework
Automated testing suite for SQL injection vulnerabilities
"""
import re
import logging
import time
from typing import List, Dict, Any
from django.test import TestCase, RequestFactory
from django.http import HttpRequest
from django.db import connection
from django.conf import settings
from core_config.sql_injection_middleware import SQLInjectionDetectionMiddleware

logger = logging.getLogger('security')


class SQLInjectionTestSuite:
    """
    Comprehensive SQL injection testing suite
    """
    
    def __init__(self):
        self.factory = RequestFactory()
        self.middleware = SQLInjectionDetectionMiddleware(lambda r: None)
        self.test_results = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'blocked_attacks': 0,
            'missed_attacks': 0,
            'false_positives': 0,
            'test_details': []
        }
    
    def run_comprehensive_tests(self) -> Dict[str, Any]:
        """
        Run comprehensive SQL injection tests
        """
        logger.info("🔒 Starting Comprehensive SQL Injection Testing...")
        
        # Test categories
        test_categories = [
            ('Basic SQL Injection', self._test_basic_sql_injection),
            ('Union-based Injection', self._test_union_injection),
            ('Boolean-based Injection', self._test_boolean_injection),
            ('Time-based Injection', self._test_time_injection),
            ('Error-based Injection', self._test_error_injection),
            ('Second-order Injection', self._test_second_order_injection),
            ('NoSQL Injection', self._test_nosql_injection),
            ('Bypass Techniques', self._test_bypass_techniques),
            ('Advanced Payloads', self._test_advanced_payloads),
            ('Safe Inputs', self._test_safe_inputs)
        ]
        
        for category_name, test_function in test_categories:
            logger.info(f"\n📋 Testing: {category_name}")
            test_function()
        
        return self._generate_test_report()
    
    def _test_basic_sql_injection(self):
        """Test basic SQL injection patterns"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "admin'--",
            "admin'/*",
            "' OR 1=1#",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 'x'='x",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Basic SQL Injection', should_block=True)
    
    def _test_union_injection(self):
        """Test UNION-based SQL injection"""
        payloads = [
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' UNION SELECT user()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables--",
            "' UNION SELECT load_file('/etc/passwd')--",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'UNION Injection', should_block=True)
    
    def _test_boolean_injection(self):
        """Test boolean-based blind SQL injection"""
        payloads = [
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' AND (SELECT LENGTH(database())) > 5--",
            "' AND (SELECT SUBSTRING(@@version,1,1)) = '5'--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 10--",
            "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
            "' AND 1=(SELECT COUNT(*) FROM tabname)--",
            "' AND MID(VERSION(),1,1) = '5'--",
            "' AND ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1)) > 64--",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Boolean Injection', should_block=True)
    
    def _test_time_injection(self):
        """Test time-based blind SQL injection"""
        payloads = [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; pg_sleep(5)--",
            "' AND (SELECT COUNT(*) FROM generate_series(1,1000000)) > 0--",
            "' UNION SELECT IF(1=1,SLEEP(5),0)--",
            "'; BENCHMARK(5000000,MD5(1))--",
            "' AND IF(1=1,SLEEP(5),0)--",
            "' OR IF(1=1,SLEEP(5),0)--",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Time-based Injection', should_block=True)
    
    def _test_error_injection(self):
        """Test error-based SQL injection"""
        payloads = [
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            "' AND EXP(~(SELECT * FROM (SELECT USER())a))--",
            "' AND GTID_SUBSET(@@version,0)--",
            "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,(SELECT @@version),0x7e)) USING utf8)))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Error-based Injection', should_block=True)
    
    def _test_second_order_injection(self):
        """Test second-order SQL injection"""
        payloads = [
            "admin'; INSERT INTO users VALUES('hacker','password')--",
            "test'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "user'; DELETE FROM logs WHERE id > 0--",
            "guest'; CREATE TABLE backdoor (cmd TEXT)--",
            "temp'; ALTER TABLE users ADD COLUMN backdoor TEXT--",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Second-order Injection', should_block=True)
    
    def _test_nosql_injection(self):
        """Test NoSQL injection patterns"""
        payloads = [
            "'; return true; var x='",
            "'; return this.username == 'admin' && this.password == 'password'; var x='",
            "admin'; return true; //",
            "'; return db.users.find(); var x='",
            "'; return db.users.drop(); var x='",
            "$where: function() { return true; }",
            "$ne: null",
            "$regex: .*",
            "$gt: ''",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'NoSQL Injection', should_block=True)
    
    def _test_bypass_techniques(self):
        """Test SQL injection bypass techniques"""
        payloads = [
            "' /**/OR/**/1=1--",
            "' %0aOR%0a1=1--",
            "' %0dOR%0d1=1--",
            "' %0a%0dOR%0a%0d1=1--",
            "' %09OR%091=1--",
            "' OR 1=1%00--",
            "' OR 1=1%16--",
            "' OR 1=1%23",
            "' OR 'x'='x'",
            "' OR \"x\"=\"x\"",
            "' OR `x`=`x`",
            "' OR [x]=[x]",
            "' UNION/**/SELECT/**/1--",
            "' UNION%0aSELECT%0a1--",
            "' UNION%0dSELECT%0d1--",
            "' UNION%09SELECT%091--",
            "' UNION%0a%0dSELECT%0a%0d1--",
            "' OR 1=1 AND ''='",
            "' OR 1=1 AND \"\"=\"",
            "' OR 1=1 AND ``=`",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Bypass Techniques', should_block=True)
    
    def _test_advanced_payloads(self):
        """Test advanced SQL injection payloads"""
        payloads = [
            "'; EXEC xp_cmdshell('dir')--",
            "'; EXEC sp_configure 'show advanced options',1--",
            "'; EXEC sp_configure 'xp_cmdshell',1--",
            "'; EXEC master..xp_cmdshell 'ping 127.0.0.1'--",
            "'; DECLARE @cmd VARCHAR(8000); SET @cmd='dir'; EXEC master..xp_cmdshell @cmd--",
            "'; INSERT INTO OPENROWSET('Microsoft.Jet.OLEDB.4.0','Excel 8.0;Database=C:\\test.xls;','SELECT * FROM [Sheet1$]') VALUES ('test')--",
            "'; SELECT * FROM OPENROWSET('SQLOLEDB','uid=sa;pwd=;Network=DBMSSOCN;Address=127.0.0.1,1433;','SELECT * FROM master..sysdatabases')--",
            "'; BULK INSERT temp FROM 'c:\\temp.txt'--",
            "'; SELECT * INTO OUTFILE '/tmp/test.txt' FROM users--",
            "'; LOAD DATA INFILE '/etc/passwd' INTO TABLE temp--",
        ]
        
        for payload in payloads:
            self._test_payload(payload, 'Advanced Payloads', should_block=True)
    
    def _test_safe_inputs(self):
        """Test legitimate inputs that should not be blocked"""
        safe_inputs = [
            "john.doe@example.com",
            "user123",
            "password123!",
            "John O'Connor",  # Legitimate apostrophe
            "SELECT * FROM my_table",  # Legitimate SQL in content
            "Price: $19.99",
            "Date: 2023-12-31",
            "Phone: +1-555-123-4567",
            "Address: 123 Main St, Apt #5",
            "Comment: This is a normal comment with punctuation!",
            "Search: python programming",
            "Title: How to use SQL databases",
            "Description: Learn about database management",
            "Tags: web, development, security",
            "URL: https://example.com/page?id=123&sort=name",
        ]
        
        for safe_input in safe_inputs:
            self._test_payload(safe_input, 'Safe Inputs', should_block=False)
    
    def _test_payload(self, payload: str, category: str, should_block: bool):
        """Test a single payload"""
        self.test_results['total_tests'] += 1
        
        # Test GET request
        request = self.factory.get('/test/', {'param': payload})
        response = self.middleware.process_request(request)
        
        was_blocked = response is not None
        test_passed = was_blocked == should_block
        
        if test_passed:
            self.test_results['passed_tests'] += 1
            if should_block and was_blocked:
                self.test_results['blocked_attacks'] += 1
        else:
            self.test_results['failed_tests'] += 1
            if should_block and not was_blocked:
                self.test_results['missed_attacks'] += 1
            elif not should_block and was_blocked:
                self.test_results['false_positives'] += 1
        
        # Record test details
        self.test_results['test_details'].append({
            'category': category,
            'payload': payload[:100],  # Truncate for logging
            'should_block': should_block,
            'was_blocked': was_blocked,
            'passed': test_passed
        })
        
        # Log result
        status = "✅ PASS" if test_passed else "❌ FAIL"
        logger.debug(f"  {status} - {category}: {payload[:50]}...")
    
    def _generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total = self.test_results['total_tests']
        passed = self.test_results['passed_tests']
        failed = self.test_results['failed_tests']
        
        if total > 0:
            success_rate = (passed / total) * 100
            detection_rate = (self.test_results['blocked_attacks'] / 
                            max(1, self.test_results['blocked_attacks'] + self.test_results['missed_attacks'])) * 100
            false_positive_rate = (self.test_results['false_positives'] / max(1, total)) * 100
        else:
            success_rate = detection_rate = false_positive_rate = 0
        
        report = {
            'summary': {
                'total_tests': total,
                'passed_tests': passed,
                'failed_tests': failed,
                'success_rate': success_rate,
                'detection_rate': detection_rate,
                'false_positive_rate': false_positive_rate,
                'blocked_attacks': self.test_results['blocked_attacks'],
                'missed_attacks': self.test_results['missed_attacks'],
                'false_positives': self.test_results['false_positives']
            },
            'details': self.test_results['test_details']
        }
        
        # Log summary
        logger.info("\n" + "=" * 60)
        logger.info("SQL INJECTION TESTING REPORT")
        logger.info("=" * 60)
        logger.info(f"Total Tests: {total}")
        logger.info(f"Passed: {passed} ({success_rate:.1f}%)")
        logger.info(f"Failed: {failed}")
        logger.info(f"Detection Rate: {detection_rate:.1f}%")
        logger.info(f"False Positive Rate: {false_positive_rate:.1f}%")
        logger.info(f"Blocked Attacks: {self.test_results['blocked_attacks']}")
        logger.info(f"Missed Attacks: {self.test_results['missed_attacks']}")
        logger.info(f"False Positives: {self.test_results['false_positives']}")
        
        # Overall assessment
        if success_rate >= 95 and detection_rate >= 90 and false_positive_rate <= 5:
            logger.info("🎉 EXCELLENT - SQL injection protection is highly effective!")
        elif success_rate >= 85 and detection_rate >= 80 and false_positive_rate <= 10:
            logger.info("✅ GOOD - SQL injection protection is effective")
        elif success_rate >= 70 and detection_rate >= 70 and false_positive_rate <= 15:
            logger.info("⚠️ FAIR - SQL injection protection needs improvement")
        else:
            logger.error("❌ POOR - SQL injection protection is inadequate")
        
        return report


class SQLInjectionCITestCase(TestCase):
    """
    Django TestCase for CI/CD pipeline integration
    """
    
    def setUp(self):
        self.test_suite = SQLInjectionTestSuite()
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection for CI/CD"""
        report = self.test_suite.run_comprehensive_tests()
        
        # Assert minimum security standards
        self.assertGreaterEqual(
            report['summary']['success_rate'], 85,
            "SQL injection protection success rate must be at least 85%"
        )
        
        self.assertGreaterEqual(
            report['summary']['detection_rate'], 80,
            "SQL injection detection rate must be at least 80%"
        )
        
        self.assertLessEqual(
            report['summary']['false_positive_rate'], 10,
            "False positive rate must be less than 10%"
        )
        
        self.assertEqual(
            report['summary']['missed_attacks'], 0,
            "No SQL injection attacks should be missed"
        )


def run_sql_injection_tests():
    """
    Convenience function to run SQL injection tests
    """
    test_suite = SQLInjectionTestSuite()
    return test_suite.run_comprehensive_tests()