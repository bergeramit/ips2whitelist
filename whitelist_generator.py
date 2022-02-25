import re

CONSTRAINT_BASIC_OPERATOR_VALUE_RE = "(?P<operator>.*)\(other=(?P<value>.*)\)"
CONSTRAINT_EXPRESSION_RE = "(?P<expression>.*)\(\)"

class WhitelistGenerator:
    STATIC_OPERATORS = {"le": '<=', "eq": '==', "lt": '<', "ge": '>='}
    DYNAMIC_OPERATORS = {
        'validate_records_amount': 'is-the-amount-of',
        'not_contain': 'not-contain',
        'is_text': 'only-contains',
        'compressions_offset': 'compression-offset-is',
        'labels': 'labels-in-the'
        }
    SUPPORTED_EXPRESSIONS = ["or", "and"]
    PROTOCOL_TO_TRANPORT_LAYER = {
        'dns': ('udp', 8),
        'tcp': ('tcp', 20),
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
        transport_protocol, protocol_payload_offset = self.PROTOCOL_TO_TRANPORT_LAYER[self.description_obj.protocol.decode('utf-8').lower()]
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

                return f"{transport_protocol}[{offset_in_bytes + protocol_payload_offset}:{size_in_bytes}] & 0x{byte_mask:x} {self.STATIC_OPERATORS[operator]} {value}"

            else:
                size_in_bytes = size_in_bits // 8
        except ValueError as e:
            return None
        
        return f"{transport_protocol}[{offset_in_bytes + protocol_payload_offset}:{size_in_bytes}] {self.STATIC_OPERATORS[operator]} {value}"

    @classmethod
    def is_dynamic_rule(cls, match_basic_rule):
        return match_basic_rule.group("operator") in cls.DYNAMIC_OPERATORS

    def create_rule_from_constraint(self, constraint_rule):
        whitelist_basic_rules = []
        expression_addon = None
        split_rule = constraint_rule.split('.')
        field_name = split_rule[0]
        entry = self.description_obj.get_entry_by_field_name(field_name)
        
        if not entry:
            # Undeclared field rule
            return None

        _, field_name, size_in_bits, offset_in_bits, dynamic_offsets = entry

        # print(f"\nsplit lines: {split_rule[1:]}\n")
        for function in split_rule[1:]:
            match_basic_rule = re.search(CONSTRAINT_BASIC_OPERATOR_VALUE_RE, function)
            match_expression_rule = re.search(CONSTRAINT_EXPRESSION_RE, function)

            if match_basic_rule:
                if self.is_dynamic_rule(match_basic_rule):
                    whitelist_full_rule = f"Dynamic {field_name.decode('utf-8')} {self.DYNAMIC_OPERATORS[match_basic_rule.group('operator')]} {match_basic_rule.group('value')}"
                    print(f"Dynamic Whitelist Rule: {whitelist_full_rule}\n")
                    return whitelist_full_rule

                # Basic rule
                basic_rule = self.generate_rule_from_elements(
                                    size_in_bits,
                                    offset_in_bits,
                                    match_basic_rule.group('operator'),
                                    match_basic_rule.group('value')
                                )
                if basic_rule:
                    # Encounter bit offset of "AtMost" bits = cannot insert rule
                    whitelist_basic_rules.append(basic_rule)

            elif match_expression_rule and match_expression_rule.group('expression') in self.SUPPORTED_EXPRESSIONS:
                expression = match_expression_rule.group('expression')
                expression_addon = f' {expression} '

        if not whitelist_basic_rules:
            # Rule unsupported
            return None

        whitelist_full_rule = expression_addon.join(whitelist_basic_rules) if expression_addon else whitelist_basic_rules[0]
        if dynamic_offsets:
            # cannot BPF rule on dynamic offsets
            print(f"WARNING: creating dynamic offset whitelist rules! will not insert to file. "
                   "Should change the byte offset of this rule")
            print(f"DROPPED rule: {whitelist_full_rule}\n")
            return None

        print(f"Whitelist Rule: {whitelist_full_rule}\n")
        return whitelist_full_rule


    def __iter__(self):
        for constraint_rule in self.description_obj.constraint_rules:
            whitelist_rule = self.create_rule_from_constraint(constraint_rule)
            if whitelist_rule:
                yield whitelist_rule, constraint_rule
