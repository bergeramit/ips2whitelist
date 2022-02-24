import re

CONSTRAINT_BASIC_OPERATOR_VALUE_RE = "(?P<operator>.*)\(other=(?P<value>\d+)\)"
CONSTRAINT_EXPRESSION_RE = "(?P<expression>.*)\(\)"

class WhitelistGenerator:
    OPERATORS = {"le": '<=', "eq": '==', "lt": '<', "ge": '>='}
    EXPRESSIONS = ["or", "and"]
    PROTOCOL_TO_TRANPORT_LAYER = {
        'dns': 'udp',
        'tcp': 'tcp'
    }

    def __init__(self, description_obj):
        self.description_obj = description_obj

    def generate_byte_mask_and_updated_value(self, size_in_bits, offset_in_bits, value):
        byte_mask = []
        offset_in_byte = int(offset_in_bits) % 8
        end_offset_in_byte = offset_in_byte + size_in_bits
        for i in range(8):
            byte_mask.append('1' if offset_in_byte <= i < end_offset_in_byte else '0')
        
        byte_mask = int("".join(byte_mask), 2)
        shift_value_amount = 8 - end_offset_in_byte
        value = int(value) << shift_value_amount
        return byte_mask, value

    def generate_rule_from_elements(self, size_in_bits, offset_in_bits, operator, value):
        transport_protocol = self.PROTOCOL_TO_TRANPORT_LAYER[self.description_obj.protocol.decode('utf-8').lower()]
        try:
            offset_in_bytes = int(offset_in_bits) // 8
            size_in_bits = int(size_in_bits)
            if size_in_bits < 8:
                '''
                This is the case where the size in bits is less then a full byte and 
                so we have to mask out some leftover bits and move the value accordingly
                '''
                size_in_bytes = 1
                byte_mask, value = self.generate_byte_mask_and_updated_value(size_in_bits, offset_in_bits, value)

                return f"{transport_protocol}[{offset_in_bytes}:{size_in_bytes}] & 0x{byte_mask:x} {self.OPERATORS[operator]} {value}"

            else:
                size_in_bytes = size_in_bits // 8
        except ValueError:
            return None
        
        return f"{transport_protocol}[{offset_in_bytes}:{size_in_bytes}] {self.OPERATORS[operator]} {value}"

    def create_rule_from_constraint(self, constraint_rule):
        whitelist_basic_rules = []
        expression_addon = None
        split_rule = constraint_rule.split('.')
        field_name = split_rule[0]
        entry = self.description_obj.get_entry_by_field_name(field_name)
        if not entry:
            return

        struct_name, field_name, size_in_bits, offset_in_bits = entry
        for function in split_rule[1:]:
            match_basic_rule = re.search(CONSTRAINT_BASIC_OPERATOR_VALUE_RE, function)
            match_expression_rule = re.search(CONSTRAINT_EXPRESSION_RE, function)
            match_basic_rule = re.search(CONSTRAINT_BASIC_OPERATOR_VALUE_RE, function)

            if match_basic_rule:
                # Basic rule
                whitelist_basic_rules.append(self.generate_rule_from_elements(
                                             size_in_bits,
                                             offset_in_bits,
                                             match_basic_rule.group('operator'),
                                             match_basic_rule.group('value')
                                             ))
                # print(f"\nfrom: {constraint_rule}")
            elif match_expression_rule:
                expression_addon = f' {match_expression_rule.group("expression")} '

        print(f"Ruels: {whitelist_basic_rules} expressoin: {expression_addon}")
        return whitelist_basic_rules[0] if not expression_addon else expression_addon.join(whitelist_basic_rules)


    def __iter__(self):
        for constraint_rule in self.description_obj.constraint_rules:
            whitelist_rule = self.create_rule_from_constraint(constraint_rule)
            if whitelist_rule:
                yield whitelist_rule
