import unittest

from asustor_nas_cli.topology import parse_disk_topology

SAMPLE = """__ADM_SYSFS_BEGIN__
__ADM_DISK__=sda|WDC WD5000HHTZ-0|976773168
__ADM_DISK__=sdb|WDC WD5000HHTZ-0|976773168
__ADM_PARTITION__=sda4|sda|4|900000000
__ADM_PARTITION__=sdb4|sdb|4|900000000
__ADM_ARRAY_MEMBER__=md1|sda4
__ADM_ARRAY_MEMBER__=md1|sdb4
__ADM_SYSFS_END__
__ADM_MDSTAT_BEGIN__
Personalities : [raid1]
md1 : active raid1 sda4[0] sdb4[1]
      450000000 blocks [2/2] [UU]
__ADM_MDSTAT_END__
__ADM_MOUNTS_BEGIN__
__ADM_VOLUME__=/dev/md1|/volume1|ext4
__ADM_MOUNTS_END__
"""


class DiskTopologyTests(unittest.TestCase):
    def test_maps_physical_disks_to_array_and_volume(self):
        report = parse_disk_topology(SAMPLE, host="192.0.2.10")
        self.assertEqual(report["host"], "192.0.2.10")
        self.assertEqual(report["summary"]["disk_count"], 2)
        self.assertEqual(report["disks"][0]["arrays"], ["md1"])
        self.assertEqual(report["arrays"][0]["member_status"], "UU")
        self.assertEqual(report["arrays"][0]["volumes"], ["/volume1"])
        self.assertNotIn("serial", report["disks"][0])
        self.assertEqual(report["summary"]["state"], "observed")

    def test_degraded_array_is_flagged(self):
        report = parse_disk_topology(SAMPLE.replace("[2/2] [UU]", "[2/1] [U_]"))
        self.assertEqual(report["summary"]["state"], "degraded")
        self.assertEqual(report["summary"]["degraded_arrays"], ["md1"])

    def test_missing_sysfs_markers_do_not_claim_complete_coverage(self):
        report = parse_disk_topology("no topology data")
        self.assertEqual(report["coverage"]["sysfs_disks"], "unknown")
        self.assertEqual(report["coverage"]["raid_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
