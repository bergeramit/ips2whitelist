import re

CONSTRAINT_OPERATOR_VALUE_RE = "(?P<operator>.*)\(other=(?P<value>\d+)\)"

class WhitelistGenerator:
    OPERATORS = ["le", "eq", "lt", "ge"]
    EXPRESSIONS = ["or", "and"]

    def __init__(self, description_obj):
        self.description_obj = description_obj

    def generate_rule_from_elements(self, size_in_bits, offset_in_bits, operator, value):
        try:
            size_in_bytes = int(int(size_in_bits) / 8)
            offset_in_bytes = int(int(offset_in_bits) / 8)
        except ValueError:
            return None
        
        return f"{self.description_obj.protocol.lower().decode('utf-8')}[{offset_in_bytes}:{size_in_bytes}] {operator} {value}"

    def create_rule_from_constraint(self, constraint_rule):
        split_rule = constraint_rule.split('.')
        field_name = split_rule[0]
        entry = self.description_obj.get_entry_by_field_name(field_name)
        if not entry:
            return

        struct_name, field_name, size_in_bits, offset_in_bits = entry
        if field_name == b"Z":
            print(f"Z = size_in_bits={size_in_bits}, offset_in_bits={offset_in_bits}")

        for function in split_rule[1:]:
            match = re.search(CONSTRAINT_OPERATOR_VALUE_RE, function)
            if match:
                whitelist_rule =  self.generate_rule_from_elements(
                                      size_in_bits,
                                      offset_in_bits,
                                      match.group('operator'),
                                      match.group('value')
                                  )
                print(f"\nfrom: {constraint_rule}")
                return whitelist_rule


    def __iter__(self):
        for constraint_rule in self.description_obj.constraint_rules:
            whitelist_rule = self.create_rule_from_constraint(constraint_rule)
            if whitelist_rule:
                yield whitelist_rule
