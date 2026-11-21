import unittest

from asustor_nas_cli.commands import parse_sections


class ParseSectionsTests(unittest.TestCase):
    def test_partial_output_keeps_only_marked_sections(self):
        output = "__ADM_SECTION_system__\nLinux\n__ADM_SECTION_network__\nlo"
        self.assertEqual(
            parse_sections(output, ("system", "storage", "network")),
            {"system": "Linux", "storage": "", "network": "lo"},
        )

    def test_out_of_order_or_duplicate_markers_return_unknown_sections(self):
        out_of_order = "__ADM_SECTION_network__\nlo\n__ADM_SECTION_system__\nLinux"
        duplicate = "__ADM_SECTION_system__\none\n__ADM_SECTION_system__\ntwo"
        expected = {"system": "", "network": ""}
        self.assertEqual(parse_sections(out_of_order, ("system", "network")), expected)
        self.assertEqual(parse_sections(duplicate, ("system", "network")), expected)

    def test_unknown_markers_do_not_leak_text_into_requested_section(self):
        output = "__ADM_SECTION_system__\nLinux\n__ADM_SECTION_unknown__\nsecret"
        self.assertEqual(parse_sections(output, ("system",)), {"system": "Linux"})


if __name__ == "__main__":
    unittest.main()
