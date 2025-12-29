FIX_PATTERN_UPDATE = """
<PatternDownload>
    <AutoUpdate>On</AutoUpdate>
    <Interval>Every 15 minutes</Interval>
</PatternDownload>
"""

FIX_HOTFIX = """
<Hotfix>
    <AllowAutoInstallOfHotFixes>Enable</AllowAutoInstallOfHotFixes>
</Hotfix>
"""

def get_backup_payload(encryption_password):
    return f"""
<BackupRestore>
    <ScheduleBackup>
        <BackupMode>Mail</BackupMode>
        <BackupPrefix>Sophos_AutoBackup</BackupPrefix>
        <EmailAddress>leanhhao0919@gmail.com</EmailAddress>
        <BackupFrequency>Daily</BackupFrequency>
        <Hour>06</Hour>
        <Minute>00</Minute>
        <EncryptionPassword>{encryption_password}</EncryptionPassword>
    </ScheduleBackup>
</BackupRestore>
"""