# HTTP Analyzer

HTTP Rule Matcher

    host123abc:http_analyzer datta$ python http_parser.py
    Select the tool to run:
    [1] Rule Matcher
    [2] Traffic Change Analyzer
    [3] Rule Regression Analyzer
    Select the tool [1|2|3]:1
    Enter HAR file location:hars/www.google.com.har
    Enter Rule file location:rules/sample.rule
    Running rule matcher...
    Writing the URL's to rules matched in file : www.google.com.har_sample.rule.out
    host123abc:http_analyzer datta$

Traffic Change Analyzer - No Change

    host123abc:http_analyzer datta$ python http_parser.py
    Select the tool to run:
    [1] Rule Matcher
    [2] Traffic Change Analyzer
    [3] Rule Regression Analyzer
    Select the tool [1|2|3]:2
    Enter old HAR file location:hars/www.google.com.har
    Enter new HAR file location:hars/www.google.com_copy.har
    Enter Rule file location:rules/sample.rule
    Running traffic change analyzer...
    Writing the URL's to rules matched in file : www.google.com.har_sample.rule.out
    Writing the URL's to rules matched in file : www.google.com_copy.har_sample.rule.out
    No traffic change found
    host123abc:http_analyzer datta$

Traffic Change Analyzer - Change

    host123abc:http_analyzer datta$ python http_parser.py
    Select the tool to run:
    [1] Rule Matcher
    [2] Traffic Change Analyzer
    [3] Rule Regression Analyzer
    Select the tool [1|2|3]:2
    Enter old HAR file location:hars/www.google.com.har
    Enter new HAR file location:hars/www.bing.com.har
    Enter Rule file location:rules/sample.rule
    Running traffic change analyzer...
    Writing the URL's to rules matched in file : www.google.com.har_sample.rule.out
    Writing the URL's to rules matched in file : www.bing.com.har_sample.rule.out
    Count of rules matched is different for both the HAR's
    host123abc:http_analyzer datta$

Rule Regression Analyzer

    host123abc:http_analyzer datta$ python http_parser.py
    Select the tool to run:
    [1] Rule Matcher
    [2] Traffic Change Analyzer
    [3] Rule Regression Analyzer
    Select the tool [1|2|3]:3
    Enter HAR file location:hars/www.google.com.har
    Enter Old Rule file location:rules/sample.rule
    Enter New Rule file location:rules/sample2.rule
    Running regression check...
    Writing the URL's to rules matched in file : www.google.com.har_sample.rule.out
    Writing the URL's to rules matched in file : www.google.com.har_sample2.rule.out
    URL:https://www.google.com/client_204?cs=1 has matched with different rules in old and new rule file, there is a regression with rule:rule_1
    host123abc:http_analyzer datta$


Test execution

    host123abc:http_analyzer datta$ python http_parser_test.py
    ..
    ----------------------------------------------------------------------
    Ran 2 tests in 0.003s
    
    OK
    host123abc:http_analyzer datta$
    host123abc:http_analyzer datta$
