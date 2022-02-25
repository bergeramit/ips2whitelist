import os
from pytest import mark
from inspect import getmembers, isfunction
import dynamic_rules_validator

PCAPS_TO_CHECK = [
    "simple_query_non_zero_Z.pcap",
    "ap2_wrong_label_size.pcap",
    "ap5_wrong_compression_offset.pcap",
    "simple_query_non_zero_Z.pcap",
    "static_rr_class_ge_4.pcap",
    "ap3_missing_null_terminator.pcap",
    "CVE-2020-11901.pcap",
    "static_non_zero_Z.pcap",
    "static_rr_qclass_ge_4_le_255.pcap",
    "whitelist_compressed_answer.pcap",
    "ap4_wrong_counts.pcap",
    "static_rcode_ge_4.pcap",
    "static_rr_type_ge_16.pcap",
    "whitelist_simple_query.pcap",
]

class FailedRule(Exception):
    pass

def find_function_by_rule(actual_rule_no_prefix):
    func_name_elements = ['validate']
    for expression in actual_rule_no_prefix:
        if '-' in expression:
            func_name_elements.append("_".join(expression.split('-')))
        else:
            func_name_elements.append(expression)
    
    target_name = "_".join(func_name_elements)
    for validate_function_name, validate_function in getmembers(dynamic_rules_validator, isfunction):
        if target_name == validate_function_name:
            return validate_function

    return lambda x: False # Fail if no function found for this rule

@mark.parametrize('pcap_path', PCAPS_TO_CHECK)
def test_static_rule(pcap_path, run_pcap_with_rule, static_whitelist_rule):
    actual_rule, rule_name = static_whitelist_rule.split(b'->')[0], static_whitelist_rule.split(b'->')[1]
    if len(run_pcap_with_rule(os.path.join('tests','test_dns', 'pcaps', pcap_path), actual_rule)) <= 0:
        raise FailedRule(f"{rule_name} on {pcap_path}")
    assert True

@mark.parametrize('pcap_path', PCAPS_TO_CHECK)
def test_dynamic_rule(pcap_path, dynamic_whitelist_rule):
    actual_rule, rule_name = dynamic_whitelist_rule.split(b' -> ')[0].decode('utf-8'), dynamic_whitelist_rule.split(b'->')[1].decode('utf-8')
    actual_rule_no_prefix = actual_rule.split(' ')[1:]
    apply_rule_function = find_function_by_rule(actual_rule_no_prefix)
    print(f"Rule based on {rule_name}")
    assert apply_rule_function(os.path.join('tests','test_dns', 'pcaps', pcap_path))
