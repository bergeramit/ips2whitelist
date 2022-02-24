import re

STRUCT_DEFINITION_RE = b"Struct \(Struct\<(?P<struct_name>.*)::"
FIELD_IN_STRUCT_RE = b"BitString \(BitString\<(?P<struct_name>\w+)_(?P<field_name>\w+)::Sized .*\>\) \[size: (?P<size_in_bits>.*) bits\]"
FIELD_NAMES_RE = b"	Field \((?P<field_name>.*)\)"
PROTOCOL_RE = b"Protocol \((?P<protocol>\w+)\)"
CONSTRAINT_RE = b"Constraint \(Self\.(?P<constraint_rule>.*)\)"

class IPSDescrption:
    def __init__(self, raw_description):
        self.raw_description = raw_description
        self.packet = []
        self.constraint_rules = []
        self.protocol = self.parse_protocol()
        self.parse_packet()
        self.parse_constraints()
    
    def get_entry_by_field_name(self, name):
        for entry in self.packet:
            if entry[1].decode('utf-8') == name:
                return entry
        return None

    def parse_protocol(self):
        for raw_line in self.raw_description:
            match = re.search(PROTOCOL_RE, raw_line)
            if match:
                return match.group('protocol')

    def parse_packet(self):
        offset_in_bits = 0
        dynamic_offsets = False
        for raw_line in self.raw_description:
            match = re.search(FIELD_IN_STRUCT_RE, raw_line)
            if match:
                struct_name, field_name, size_in_bits = match.group('struct_name'), match.group('field_name'), match.group('size_in_bits')
                self.packet.append((struct_name, field_name, size_in_bits, offset_in_bits, dynamic_offsets))
                try:
                    offset_in_bits += int(size_in_bits)
                except ValueError:
                    dynamic_offsets = True # cannot measure dynamic offsets in static parsing
                    offset_in_bits = 0

    def parse_constraints(self):
        for raw_line in self.raw_description:
            match = re.search(CONSTRAINT_RE, raw_line)
            if match:
                self.constraint_rules.append(match.group('constraint_rule').decode('utf-8'))

    def display(self):
        print(f"Descrption for Protocol: {self.protocol.decode('utf-8')}")
        print("Packet Struct:")
        for struct_name, field_name, size_in_bits, _, _ in self.packet:
            try:
                print(f"{struct_name.decode('utf-8')}.{field_name.decode('utf-8')} : {int(size_in_bits)} bits")
            except ValueError:
                print(f"{struct_name.decode('utf-8')}.{field_name.decode('utf-8')} : {size_in_bits.decode('utf-8')} bits (dynamic offsets)")

        print(f"Constraints")
        for constraint_rule in self.constraint_rules:
            print(constraint_rule)
