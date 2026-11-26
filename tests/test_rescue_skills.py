#!/usr/bin/env python3
"""Tests for the five domain skills of the Hermes rescue profile (ahliweb/linux-mint-xfce-rescue-ai#89).

The skills are instructions, not code, so these tests pin what can be pinned: front matter, that every
check ID and every action_id they name exists (a skill must not invent either), that the data-safety skill
covers every irreversible and destructive catalog action, that the Android and USB cable and port rules are
present, and that no skill tells Hermes to use an approval flag.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / 'profiles/rescue-hermes/skills'
NEW_SKILLS = ('rescue-hardware', 'rescue-data-safety', 'rescue-malware', 'rescue-host-repair', 'rescue-software')

ACTION_ID = re.compile(r'^(?:hw|sw|mw|os-linux|os-windows|os-macos|android|printer)\.[a-z0-9-]+$')
CHECK_ID = re.compile(r'^(?:hw|sw|malware|android|usb|printer)-[a-z0-9-]+$')
PLAIN_CHECK_IDS = {'smart-health', 'nvme-health', 'disk-free-space', 'encryption-status'}
# Values that look like a check ID but are evidence `access` values.
NOT_CHECKS = {'usb-only'}
# Named only to say that it does not exist.
NEGATED_ACTIONS = {'mw.defender-remove-threats'}
APPROVAL_FLAGS = ('--approve', '--param', '--backup-ref')


def read(name):
    return (SKILLS_DIR / name / 'SKILL.md').read_text(encoding='utf-8')


def catalog_actions():
    actions = {}
    for path in sorted((ROOT / 'rescue-ai/v1/catalog').glob('*.json')):
        for action in json.loads(path.read_text(encoding='utf-8'))['actions']:
            actions[action['action_id']] = action
    return actions


def schema_check_ids():
    schema = json.loads((ROOT / 'rescue-ai/v1/rescue-evidence.schema.json').read_text(encoding='utf-8'))
    return set(schema['properties']['checks']['items']['properties']['check_id']['enum'])


def backticked(text):
    return re.findall(r'`([^`\n]+)`', text)


class TestNewSkills(unittest.TestCase):
    def test_all_five_exist_with_valid_front_matter(self):
        for name in NEW_SKILLS:
            text = read(name)
            m = re.match(r'^---\n(.*?)\n---\n', text, re.S)
            self.assertIsNotNone(m, name)
            fields = dict(line.split(': ', 1) for line in m.group(1).splitlines() if ': ' in line)
            self.assertEqual(set(fields), {'name', 'description'}, name)
            self.assertEqual(fields['name'], name)
            self.assertGreater(len(fields['description']), 60, name)
            self.assertIn('Bahasa Indonesia', text, name)   # answers to the operator are in Indonesian
            self.assertIn('Model output is never executed', text, name)
            self.assertIn('`unknown` stays unknown', text, name)

    def test_every_action_id_named_exists_in_the_catalog(self):
        actions = catalog_actions()
        for name in NEW_SKILLS:
            for token in backticked(read(name)):
                if ACTION_ID.match(token) and token not in NEGATED_ACTIONS:
                    self.assertIn(token, actions, '%s names an unknown action_id: %s' % (name, token))

    def test_negated_actions_are_only_named_as_missing(self):
        for name in NEW_SKILLS:
            for line in read(name).splitlines():
                for action in NEGATED_ACTIONS:
                    if action in line:
                        self.assertRegex(line, r'(?i)\b(no|not|never)\b', line)
                        self.assertNotIn(action, catalog_actions())

    def test_every_check_id_named_exists_in_the_evidence_schema(self):
        known = schema_check_ids()
        for name in NEW_SKILLS:
            for token in backticked(read(name)):
                if token in NOT_CHECKS:
                    continue
                if CHECK_ID.match(token) or token in PLAIN_CHECK_IDS:
                    self.assertIn(token, known, '%s names an unknown check ID: %s' % (name, token))

    def test_no_skill_tells_hermes_to_use_an_approval_flag(self):
        for name in NEW_SKILLS:
            for line in read(name).splitlines():
                if any(flag in line for flag in APPROVAL_FLAGS):
                    self.assertRegex(line, r'(?i)never|denies|operator|engine', '%s: %s' % (name, line))

    def test_no_identifiers_or_secrets_in_the_skills(self):
        for name in NEW_SKILLS:
            text = read(name)
            self.assertNotRegex(text, r'\b\d{1,3}(?:\.\d{1,3}){3}\b', name)
            self.assertNotRegex(text, r'[\w.+-]+@[\w-]+\.[\w.-]+', name)
            self.assertNotRegex(text, r'(?<![\w.])/(?:home|Users|media|mnt)/', name)
            self.assertNotIn('```', text, name)   # no command blocks: skills name IDs, never commands


class TestDataSafety(unittest.TestCase):
    def test_covers_every_irreversible_and_destructive_action(self):
        text = read('rescue-data-safety')
        for action_id, action in catalog_actions().items():
            if action['risk'] == 'irreversible':
                self.assertIn('`%s`' % action_id, text, action_id)
            elif action['risk'] == 'destructive':
                prefix = action_id.split('.', 1)[0]
                self.assertTrue('`%s`' % action_id in text or '`%s.*`' % prefix in text, action_id)

    def test_states_that_nothing_backs_up_a_phone(self):
        text = read('rescue-data-safety')
        for needle in ('No check and no catalog action backs up a phone', '`adb pull`', 'fastboot cannot read a partition back',
                       'erases all user data', 'android.fastboot-set-active-slot', 'android.fastboot-update-image',
                       'qualcomm-edl', 'not-mounted-encrypted', '`--backup-ref`'):
            self.assertIn(needle, text)
        self.assertIn('the answer to "can Hermes back up my phone" is no', text)

    def test_never_offers_to_perform_a_backup(self):
        text = read('rescue-data-safety')
        self.assertIn('Hermes never copies, images, pulls, or restores data', text)
        self.assertIn('Never say it is safe to skip a backup', text)


class TestHardware(unittest.TestCase):
    def test_usb_cable_and_port_for_a_phone(self):
        text = read('rescue-hardware')
        for needle in ('charge-only', 'usb-android-device-count', 'android-usb-port-speed', 'android-connection-mode',
                       'hw-usb', 'is_boot_media: true', 'Transfer file (MTP)', 'There is no check for cable quality',
                       'rescue-android', 'rescue-printer', 'rescue-data-safety'):
            self.assertIn(needle, text)

    def test_names_exactly_the_four_hardware_actions(self):
        text = read('rescue-hardware')
        named = {t for t in backticked(text) if t.startswith('hw.')}
        self.assertEqual(named, {a for a in catalog_actions() if a.startswith('hw.')})


class TestMalwareAndHostAndSoftware(unittest.TestCase):
    def test_malware_keeps_the_detection_list_private(self):
        text = read('rescue-malware')
        for needle in ('malware-detections-', 'd-N', 'quarantine', 'always ask', 'not proof of absence',
                       'There is no malware scanner for phones', 'macOS', '`malware-scan`'):
            self.assertIn(needle, text)

    def test_host_repair_states_the_macos_catalog_is_empty_and_no_elevation(self):
        text = read('rescue-host-repair')
        for needle in ('macos-host', 'The macOS catalog is empty', 'never elevates', 'needs-root', 'Hardware-required',
                       'provider-unavailable'):
            self.assertIn(needle, text)

    def test_software_does_not_present_planned_work_as_available(self):
        text = read('rescue-software')
        line = next(l for l in text.splitlines() if 'RPM' in l)
        self.assertIn('Planned', line)
        for action_id, action in catalog_actions().items():
            if action_id.startswith('sw.'):
                self.assertEqual(action['risk'], 'destructive', action_id)
                self.assertIn('`%s`' % action_id, text, action_id)


class TestCrossLinksAndRegistration(unittest.TestCase):
    def test_android_links_to_the_new_skills_and_keeps_its_rules(self):
        text = read('rescue-android')
        for needle in ('rescue-hardware', 'rescue-data-safety', 'rescue-malware'):
            self.assertIn(needle, text)
        # The pre-existing rules are unchanged.
        self.assertIn('There are exactly three adb catalog actions', text)
        forbidden = text.split('## Forbidden actions', 1)[1].split('## Related skills', 1)[0]
        self.assertIn('`adb pull`', forbidden)
        self.assertIn('Never propose any flashing action', forbidden)

    def test_registered_in_the_profile_and_the_learning_loop(self):
        agents = (ROOT / 'profiles/rescue-hermes/AGENTS.md').read_text(encoding='utf-8')
        loop = (ROOT / 'docs/hermes-learning-loop.md').read_text(encoding='utf-8')
        for name in NEW_SKILLS:
            self.assertIn('`%s`' % name, agents, name)
            self.assertIn('`%s`' % name, loop, name)

    def test_the_profile_ships_exactly_the_expected_skills(self):
        shipped = {p.parent.name for p in SKILLS_DIR.glob('*/SKILL.md')}
        self.assertTrue(set(NEW_SKILLS) <= shipped)


if __name__ == '__main__':
    unittest.main()
