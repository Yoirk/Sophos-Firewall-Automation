# --- 1.1.1 & 1.1.2 ---
# Cấu hình tự động đăng xuất, khóa tài khoản (1.1.1) và bật Disclaimer (1.1.2)
FIX_ADMIN_SETTINGS = """
<AdminSettings>
    <LoginSecurity>
        <LogoutSession>10</LogoutSession>
        <BlockLogin>Enable</BlockLogin>
        <BlockLoginSettings>
            <UnsucccessfulAttempt>5</UnsucccessfulAttempt>
            <Duration>60</Duration>
            <ForMinutes>5</ForMinutes>
        </BlockLoginSettings>
    </LoginSecurity>
    <LoginDisclaimer>Enable</LoginDisclaimer>
</AdminSettings>
"""

# --- 1.1.5 ---
# Cấu hình độ phức tạp mật khẩu chi tiết (Độ dài >= 10, Ký tự đặc biệt)
FIX_PASSWORD_COMPLEXITY = """
<AdminSettings>
    <PasswordComplexitySettings>
        <PasswordComplexityCheck>Enable</PasswordComplexityCheck>
        <PasswordComplexity>
            <MinimumPasswordLength>Enable</MinimumPasswordLength>
            <MinimumPasswordLengthValue>10</MinimumPasswordLengthValue>
            <IncludeAlphabeticCharacters>Enable</IncludeAlphabeticCharacters>
            <IncludeNumericCharacter>Enable</IncludeNumericCharacter>
            <IncludeSpecialCharacter>Enable</IncludeSpecialCharacter>
        </PasswordComplexity>
    </PasswordComplexitySettings>
</AdminSettings>
"""

# --- 1.1.3 ---
FIX_NTP = """
<Time>
    <TimeZone>Asia/Ho_Chi_Minh</TimeZone>
    <CustomNTPServer>
        <NTPServer>time.windows.com</NTPServer>
    </CustomNTPServer>
</Time>
"""

# --- 1.1.6 ---
# Tắt toàn bộ dịch vụ quản trị và mạng rủi ro trên vùng WAN
FIX_WAN_ACCESS = """
<Zone>
    <Name>WAN</Name>
    <ApplianceAccess>
        <AdminServices>
            <HTTPS>Disable</HTTPS>
            <SSH>Disable</SSH>
        </AdminServices>
        <NetworkServices>
            <DNS>Disable</DNS>
            <Ping>Disable</Ping>
        </NetworkServices>
        <OtherServices>
            <SMTPRelay>Disable</SMTPRelay>
            <SNMP>Disable</SNMP>
        </OtherServices>
    </ApplianceAccess>
</Zone>
"""