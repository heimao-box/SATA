/*
    钓鱼邮件检测YARA规则
    用于检测常见的钓鱼邮件模式和特征
*/

rule Phishing_Urgent_Action_Required
{
    meta:
        description = "检测要求紧急行动的钓鱼邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        $urgent1 = "urgent" nocase
        $urgent2 = "紧急" nocase
        $urgent3 = "immediate" nocase
        $urgent4 = "立即" nocase
        $action1 = "action required" nocase
        $action2 = "需要操作" nocase
        $action3 = "必须操作" nocase
        $verify1 = "verify" nocase
        $verify2 = "验证" nocase
        
    condition:
        any of ($urgent*) and any of ($action*, $verify*)
}

rule Phishing_Account_Verification
{
    meta:
        description = "检测账户验证类钓鱼邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $account1 = "account" nocase
        $account2 = "账户" nocase
        $account3 = "账号" nocase
        $verify1 = "verify" nocase
        $verify2 = "verification" nocase
        $verify3 = "验证" nocase
        $verify4 = "确认" nocase
        $suspend1 = "suspended" nocase
        $suspend2 = "暂停" nocase
        $suspend3 = "冻结" nocase
        $click1 = "click here" nocase
        $click2 = "点击这里" nocase
        
    condition:
        any of ($account*) and any of ($verify*) and (any of ($suspend*) or any of ($click*))
}

rule Phishing_Security_Alert
{
    meta:
        description = "检测安全警告类钓鱼邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $security1 = "security alert" nocase
        $security2 = "安全警告" nocase
        $security3 = "security warning" nocase
        $security4 = "安全提醒" nocase
        $breach1 = "breach" nocase
        $breach2 = "泄露" nocase
        $breach3 = "入侵" nocase
        $compromise1 = "compromised" nocase
        $compromise2 = "被盗" nocase
        $update1 = "update" nocase
        $update2 = "更新" nocase
        
    condition:
        any of ($security*) and (any of ($breach*, $compromise*) or any of ($update*))
}

rule Phishing_Fake_Bank_Email
{
    meta:
        description = "检测虚假银行邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $bank1 = "bank" nocase
        $bank2 = "银行" nocase
        $bank3 = "banking" nocase
        $login1 = "login" nocase
        $login2 = "登录" nocase
        $password1 = "password" nocase
        $password2 = "密码" nocase
        $expire1 = "expire" nocase
        $expire2 = "过期" nocase
        $expire3 = "失效" nocase
        $confirm1 = "confirm" nocase
        $confirm2 = "确认" nocase
        
    condition:
        any of ($bank*) and (any of ($login*, $password*) or any of ($expire*, $confirm*))
}

rule Phishing_Suspicious_Links
{
    meta:
        description = "检测包含可疑链接的邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        $ip_link = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $short_link1 = "bit.ly" nocase
        $short_link2 = "tinyurl" nocase
        $short_link3 = "t.co" nocase
        $short_link4 = "goo.gl" nocase
        $suspicious_domain1 = /https?:\/\/[a-z0-9\-]{20,}\.com/
        $suspicious_domain2 = /https?:\/\/[a-z0-9]*-[a-z0-9]*-[a-z0-9]*-[a-z0-9]*\./
        
    condition:
        any of them
}

rule Phishing_Prize_Scam
{
    meta:
        description = "检测奖品诈骗邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        $prize1 = "prize" nocase
        $prize2 = "奖品" nocase
        $prize3 = "奖励" nocase
        $winner1 = "winner" nocase
        $winner2 = "获奖者" nocase
        $winner3 = "中奖" nocase
        $congratulations1 = "congratulations" nocase
        $congratulations2 = "恭喜" nocase
        $claim1 = "claim" nocase
        $claim2 = "领取" nocase
        $free1 = "free" nocase
        $free2 = "免费" nocase
        
    condition:
        (any of ($prize*, $winner*) and any of ($congratulations*, $claim*)) or 
        (any of ($free*) and any of ($prize*, $winner*))
}

rule Phishing_CEO_Fraud
{
    meta:
        description = "检测CEO欺诈邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $ceo1 = "CEO" nocase
        $ceo2 = "总裁" nocase
        $ceo3 = "总经理" nocase
        $urgent1 = "urgent" nocase
        $urgent2 = "紧急" nocase
        $confidential1 = "confidential" nocase
        $confidential2 = "机密" nocase
        $transfer1 = "transfer" nocase
        $transfer2 = "转账" nocase
        $payment1 = "payment" nocase
        $payment2 = "付款" nocase
        
    condition:
        any of ($ceo*) and any of ($urgent*) and 
        (any of ($confidential*) or any of ($transfer*, $payment*))
}

rule Phishing_Emotional_Manipulation
{
    meta:
        description = "检测情感操纵类钓鱼邮件"
        author = "Security Team"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        $fear1 = "fear" nocase
        $fear2 = "害怕" nocase
        $fear3 = "恐惧" nocase
        $worry1 = "worry" nocase
        $worry2 = "担心" nocase
        $panic1 = "panic" nocase
        $panic2 = "恐慌" nocase
        $threat1 = "threat" nocase
        $threat2 = "威胁" nocase
        $danger1 = "danger" nocase
        $danger2 = "危险" nocase
        $limited1 = "limited time" nocase
        $limited2 = "限时" nocase
        
    condition:
        (any of ($fear*, $worry*, $panic*) or any of ($threat*, $danger*)) and
        any of ($limited*)
}

rule Phishing_Typosquatting
{
    meta:
        description = "检测域名仿冒"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $fake_google = /https?:\/\/[a-z]*goog1e[a-z]*\./
        $fake_microsoft = /https?:\/\/[a-z]*microsft[a-z]*\./
        $fake_paypal = /https?:\/\/[a-z]*payp4l[a-z]*\./
        $fake_amazon = /https?:\/\/[a-z]*amaz0n[a-z]*\./
        $fake_apple = /https?:\/\/[a-z]*app1e[a-z]*\./
        $fake_alipay = /https?:\/\/[a-z]*a1ipay[a-z]*\./
        
    condition:
        any of them
}