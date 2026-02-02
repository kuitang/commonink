# Privacy Policy

**Effective Date:** [DATE]
**Last Updated:** [DATE]

## 1. Introduction

This Privacy Policy explains how Remote Notes ("we," "us," or "our") collects, uses, and protects your personal information when you use our service.

## 2. Data We Collect

### 2.1 Account Data
- **From Google Sign-In:** Email address, name, profile picture (Google `sub` claim)
- **Purpose:** Account creation and authentication
- **Legal Basis:** Necessary for contract performance (providing the service)

### 2.2 Content Data
- **Notes:** Titles, content, tags you create
- **Metadata:** Creation/modification timestamps
- **Purpose:** Providing the notes storage and retrieval service
- **Legal Basis:** Contract performance
- **Encryption:** All note content is encrypted at rest using AES-256

### 2.3 Usage Data
- **Access Logs:** IP addresses, timestamps, endpoints accessed
- **Purpose:** Security monitoring, abuse prevention, service improvement
- **Legal Basis:** Legitimate interest (security and service quality)
- **Retention:** 90 days

### 2.4 Payment Data
- **Billing Information:** Processed by Stripe, Inc.
- **What We Store:** Subscription status, subscription ID (not full card details)
- **What Stripe Stores:** Payment methods, billing address
- **See:** [Stripe Privacy Policy](https://stripe.com/privacy)

## 3. How We Use Your Data

We use your data exclusively for:

- **Authentication:** Verifying your identity via Google OIDC
- **Service Provision:** Storing, retrieving, and searching your notes
- **Billing:** Managing subscriptions and payment processing
- **Security:** Detecting and preventing unauthorized access
- **Service Improvement:** Analyzing anonymized usage patterns (aggregated only, no individual tracking)

**We never:**
- Sell your data to third parties
- Use your note content for AI training
- Share your data for advertising purposes

## 4. Data Sharing

We share your data only with:

| Recipient | Data Shared | Purpose |
|-----------|-------------|---------|
| **Google** | Email (during OAuth flow only) | Authentication |
| **Stripe** | Email, subscription status | Payment processing |
| **AI Assistants** (Claude, ChatGPT) | Notes content (when you connect your account) | Providing MCP integration you requested |
| **Fly.io** (infrastructure provider) | Encrypted database files, logs | Service hosting |

**Third-Party Processors:**
These parties process data on our behalf under strict data processing agreements:
- **Fly.io:** Infrastructure hosting (SOC 2 Type II certified)
- **Stripe:** Payment processing (PCI DSS Level 1 compliant)

**AI Assistant Access:**
When you connect Claude or ChatGPT to your account:
- They can access your notes based on your conversation with them
- You are granting them access under their respective privacy policies:
  - [Anthropic Privacy Policy](https://www.anthropic.com/privacy)
  - [OpenAI Privacy Policy](https://openai.com/privacy)
- **You remain the data controller** of your notes
- You can revoke access at any time via Settings

## 5. Your Rights (GDPR, CCPA, UK DPA)

You have the right to:

### 5.1 Access
Request a copy of all data we hold about you.
**How:** Email privacy@[your-domain] or use Settings → Export Data

### 5.2 Rectification
Correct inaccurate data.
**How:** Edit directly in the web interface or contact support

### 5.3 Deletion ("Right to be Forgotten")
Request complete deletion of your account and data.
**How:** Settings → Delete Account, or email privacy@[your-domain]
**Timeline:** Deletion completed within 30 days; backups purged within 90 days

### 5.4 Data Portability
Export your data in machine-readable format (JSON).
**How:** Settings → Export Data

### 5.5 Objection
Object to processing based on legitimate interest.
**How:** Email privacy@[your-domain]

### 5.6 Restrict Processing
Request temporary restriction while disputing accuracy or lawfulness.
**How:** Email privacy@[your-domain]

**Response Time:** We will respond to all requests within 30 days.

## 6. Data Retention

| Data Type | Retention Period | Rationale |
|-----------|------------------|-----------|
| Active accounts | Duration of account | Service provision |
| Deleted accounts | Removed within 30 days | Compliance |
| Backup retention | Purged within 90 days | Disaster recovery |
| Access logs | 90 days | Security monitoring |
| Payment records | 7 years (as required by tax law) | Legal compliance |

## 7. Security Measures

We implement industry-standard security practices:

### 7.1 Encryption
- **At Rest:** AES-256 encryption for all note content (SQLCipher)
- **In Transit:** TLS 1.3 for all connections
- **Key Management:** Master key stored in Fly.io secrets; per-user key derivation using HKDF

### 7.2 Access Controls
- **Authentication:** OAuth 2.1 with PKCE for AI clients; Google OIDC for users
- **Authorization:** Role-based access control; strict user isolation
- **Database:** One encrypted SQLite file per user (cannot access other users' data)

### 7.3 Monitoring
- Access logging and anomaly detection
- Regular security audits
- Vulnerability scanning

### 7.4 Incident Response
- **Data Breach Notification:** We will notify affected users within 72 hours of discovery
- **Contact:** security@[your-domain]

## 8. Cookies and Tracking

### 8.1 Essential Cookies
- **Session cookie:** Required for authentication (expires on logout or 30 days)
- **OAuth state:** Temporary CSRF protection during authentication flow

### 8.2 Analytics
- **No third-party analytics** (no Google Analytics, no tracking pixels)
- Server-side aggregated metrics only (e.g., total API requests per day)

## 9. International Data Transfers

- **Primary Storage:** United States (Fly.io regions)
- **Transfers:** Data may be transferred to US, EU, or other regions where our infrastructure operates
- **Protections:** Standard Contractual Clauses (SCCs) for EU data transfers

**For EU Users:**
Your data is protected under GDPR. Our legal basis for transfers is SCCs approved by the European Commission.

## 10. Children's Privacy

Our service is **not intended for users under 18**. We do not knowingly collect data from children. If you believe a child has created an account, contact us immediately at privacy@[your-domain].

## 11. Changes to This Policy

We may update this policy to reflect:
- Changes in legal requirements
- New features or services
- Security improvements

**Notification:**
- Material changes: Email notification 30 days in advance
- Minor changes: Posted on this page with updated "Last Updated" date

**Your Options:**
If you disagree with changes, you may delete your account before the effective date.

## 12. Contact Us

**Data Protection Officer:** [If applicable for companies >250 employees or large-scale processing]
**Email:** privacy@[your-domain]
**Mail:** [Physical address]

**For EU Users:**
You have the right to lodge a complaint with your local supervisory authority. Find yours at: https://edpb.europa.eu/about-edpb/board/members_en

---

## Appendix: Data Processing Details

### Google Sign-In Data Flow
1. You click "Sign in with Google"
2. Google authenticates you
3. Google sends us: email, name, profile picture, unique ID (`sub`)
4. We create/retrieve your account
5. We create a session cookie
6. **We do NOT access your Gmail, Google Drive, or other Google services**

### AI Connector Data Flow
1. You add our connector in Claude/ChatGPT
2. AI client performs OAuth flow
3. You consent to sharing your notes
4. AI client receives OAuth token
5. AI client sends MCP requests with token
6. We return only YOUR notes (user isolation enforced)
7. AI client processes notes according to its privacy policy
8. **We log:** Which notes were accessed, when (for your security audit)
9. **We do NOT log:** The content of your conversations with AI

### Encryption Key Flow
```
Master Key (Fly secret, never leaves infrastructure)
    ↓
User KEK (derived per-user using HKDF)
    ↓
User DEK (encrypted with KEK, stored in DB)
    ↓
SQLite Database (encrypted with DEK)
```

**Key Rotation:**
We may rotate your KEK for security. This is transparent to you (no action required).

**Key Access:**
- We CAN decrypt your notes (to provide the service)
- We CANNOT read your notes without your active session or valid OAuth token
- Employees do NOT have access to decrypted note content in normal operations
- Emergency access (e.g., law enforcement request) requires legal process

---

**Version History:**
- v1.0 (2026-02-02): Initial publication
