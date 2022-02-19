import re

CONSTRAINT_OPERATOR_VALUE_RE = "(?P<operator>.*)\(other=(?P<value>\d+)\)"

class WhitelistGenerator:
    OPERATORS = {"le": '<=', "eq": '==', "lt": '<', "ge": '>='}
    EXPRESSIONS = ["or", "and"]

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

                return f"{self.description_obj.protocol.lower().decode('utf-8')}[{offset_in_bytes}:{size_in_bytes}] & 0x{byte_mask:x} {self.OPERATORS[operator]} {value}"

            else:
                size_in_bytes = size_in_bits // 8
        except ValueError:
            return None
        
        return f"{self.description_obj.protocol.lower().decode('utf-8')}[{offset_in_bytes}:{size_in_bytes}] {self.OPERATORS[operator]} {value}"

    def create_rule_from_constraint(self, constraint_rule):
        split_rule = constraint_rule.split('.')
        field_name = split_rule[0]
        entry = self.description_obj.get_entry_by_field_name(field_name)
        if not entry:
            return

        struct_name, field_name, size_in_bits, offset_in_bits = entry
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
