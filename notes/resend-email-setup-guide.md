# Resend Email Provider Setup Guide

## Table of Contents
1. [Getting Started with Resend](#getting-started-with-resend)
2. [Domain Verification](#domain-verification)
3. [Free Tier Limits & Pricing](#free-tier-limits--pricing)
4. [Email Deliverability Best Practices](#email-deliverability-best-practices)
5. [Template System](#template-system)
6. [Transactional vs Marketing Emails](#transactional-vs-marketing-emails)
7. [GDPR & Legal Compliance](#gdpr--legal-compliance)
8. [Bounce & Complaint Handling](#bounce--complaint-handling)
9. [Webhooks & API Integration](#webhooks--api-integration)
10. [Email Type Decision Matrix](#email-type-decision-matrix)

---

## Getting Started with Resend

### Sign Up Process
1. Visit [resend.com](https://resend.com/) and create an account
2. Free tier available with no credit card required

### API Keys (Test vs Production)

#### Creating API Keys
1. Navigate to "API Keys" in the main sidebar
2. Click "Create API Key"
3. Provide a descriptive name (e.g., `my-app-key`, `production-api`, `development-api`)
4. Select permissions:
   - **full_access**: Create, delete, get, and update any resource
   - **sending_access**: Only send emails (recommended for production)
5. Select the domain for which the API key will be enabled
6. Copy the API key immediately (it's only shown once)

#### Security Best Practices
- Store API keys in environment variables or secrets management systems
- Never commit API keys to version control
- Use separate API keys for development and production environments
- Use `sending_access` permissions for production to limit potential security exposure

---

## Domain Verification

### Required DNS Records

Resend requires two main DNS entries for domain authentication:

1. **SPF (Sender Policy Framework)**: List of IP addresses authorized to send email on behalf of your domain
2. **DKIM (DomainKeys Identified Mail)**: Public key used to verify email authenticity
3. **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: Optional but recommended for building trust with mailbox providers

### Setup Process

#### Step 1: Add Your Domain
1. Go to **Domains** in the Resend dashboard
2. Click **Add Domain**
3. Enter your domain or subdomain (e.g., `mail.yourdomain.com`)

#### Step 2: Add DNS Records
Resend will provide specific DNS records that need to be added to your DNS provider:

- **Automatic setup**: If you use Cloudflare, you can use automatic configuration
- **Manual setup**: Copy/paste the DNS records (DKIM, SPF, and DMARC) to your DNS provider

Example DNS records format:
```
TXT  _dmarc.yourdomain.com     v=DMARC1; p=none; ...
TXT  resend._domainkey         k=rsa; p=MIGfMA0GCS...
TXT  yourdomain.com            v=spf1 include:amazonses.com ~all
```

#### Step 3: Verify DNS Records
1. Click **Check DNS** next to your domain in Resend
2. Resend will query each record and update status indicators
3. DNS propagation can take up to 24 hours
4. Use [dns.email](https://dns.email) to check if DNS records are properly configured

#### Best Practice: Use Subdomains
- Send emails from a subdomain (e.g., `mail.yourdomain.com`) instead of your root domain
- If there's an issue with your marketing subdomain reputation, it won't impact your transactional subdomain
- Consider separate subdomains for transactional vs marketing:
  - `mail.yourdomain.com` for transactional
  - `news.yourdomain.com` for marketing

---

## Free Tier Limits & Pricing

### Free Tier (2026)

**Transactional Emails:**
- **3,000 emails per month** (30x increase from previous 100/month limit)
- **100 emails per day** rate limit
- **1 domain** per team

**Marketing Emails (Broadcasts):**
- **1,000 contacts** with unlimited email sends
- Includes WYSIWYG editor for creating campaigns

### Paid Plans

#### Transactional Email Pricing
| Plan | Monthly Cost | Emails Included | Additional Emails |
|------|--------------|-----------------|-------------------|
| Pro | $20 | 50,000 | Pay-as-you-go available |
| Scale | $90 | 100,000 | Pay-as-you-go available |
| Enterprise | Custom | 3M+ | Custom pricing |

#### Marketing Email Pricing
| Plan | Monthly Cost | Contacts | Email Sends |
|------|--------------|----------|-------------|
| Free | $0 | 1,000 | Unlimited |
| Pro | $40 | 5,000 | Unlimited |

#### Key Features by Tier
- **Free**: Basic features, 1 domain, community support
- **Pro**: Multiple domains, longer data retention, priority support
- **Enterprise**: Dedicated support, custom SLAs, volume discounts

#### Pay-as-you-go
- Available for paid transactional email plans
- Continue sending beyond quota during temporary spikes without upgrading
- Automatic scaling for traffic spikes

---

## Email Deliverability Best Practices

### Authentication (Handled by Resend)
When you add a domain to Resend, SPF and DKIM are automatically handled. You just need to add the DNS records they provide.

#### SPF (Sender Policy Framework)
- Declares which servers can send email for your domain
- Inbox providers verify the message matches authorized servers

#### DKIM (DomainKeys Identified Mail)
- Adds a signature to each message
- Verifies the email sender is who they claim to be
- Uses private/public key pairing

#### DMARC (Domain-based Message Authentication, Reporting & Conformance)
- Establishes your policy for what happens if emails fail DKIM or SPF
- Policies: `none`, `quarantine`, or `reject`
- Implementing DMARC with strict policies enhances domain reputation

### Best Practices

#### 1. Use Subdomains
- Send from `mail.yourdomain.com` instead of `yourdomain.com`
- Protects root domain reputation if subdomain has issues

#### 2. Match URLs to Sending Domain
- Ensure URLs in email body match the sending domain
- Mismatched URLs trigger spam filters

#### 3. Avoid Link Tracking for Transactional Emails
- Link tracking and open tracking can hurt deliverability
- Suspicious redirects make emails look suspicious to mailboxes
- Best for notifications and magic links to avoid tracking

#### 4. Maintain Clean Lists
- Keep bounce rates below **4%**
- Keep complaint rates under **0.08%**
- Exceeding these thresholds damages domain reputation

#### 5. Separate Email Streams
- Keep transactional and marketing emails on separate streams
- Use different IP addresses for high-volume sending
- Marketing emails have lower engagement, which can impact deliverability

#### 6. Warm Up New Domains
- Start with low volume when using a new domain
- Gradually increase sending volume
- Establishes positive sender reputation

---

## Template System

### Overview
Resend provides a modern template system with versioning and support for both HTML and React-based email development.

### Key Features

#### 1. Template Storage & Variables
- Templates are stored on Resend servers
- Reference templates by ID when sending
- Send only Template ID and variables instead of full HTML
- Resend renders final email with actual values
- Each template supports up to **20 variables**

#### 2. Creating Templates
Three ways to create templates:
1. **Dashboard**: Visual interface for creating templates
2. **Import HTML**: Upload existing HTML email code
3. **React Email**: Import React Email components
4. **API**: Programmatically create templates

#### 3. React Email Support
- Powered by [react-email](https://github.com/resend/react-email) (open source)
- Build emails using React components
- No need to deal with table layouts and complex HTML
- Works with Tailwind CSS for styling

Example React Email component:
```tsx
import { Button, Html, Text } from '@react-email/components';

export default function WelcomeEmail({ name }) {
  return (
    <Html>
      <Text>Welcome, {name}!</Text>
      <Button href="https://example.com">Get Started</Button>
    </Html>
  );
}
```

#### 4. Version Control
- Templates use versioning system
- Tracks all changes
- Keeps previous versions for rollback
- Prevents accidental email changes in production

#### 5. Publishing Workflow
- Templates start in **draft** state
- Must be **published** before use
- Publish via dashboard or API
- Only published templates can send emails

### Use Cases
- Transactional emails (password reset, magic login, order confirmations)
- Recurring email patterns
- Consistent branding across all communications
- Easy A/B testing with multiple template versions

---

## Transactional vs Marketing Emails

### Resend Support for Both Email Types

**Key Feature**: Resend allows you to send both transactional and marketing emails from the same platform, providing:
- Unified billing
- Centralized domain authentication
- Consolidated deliverability metrics
- Single source of truth for all emails

### Transactional Emails

**Definition**: Messages triggered by user action or required for legal compliance. Users **cannot** unsubscribe from these.

**Examples:**
- Password resets
- Magic login links
- Email verification
- Order confirmations
- Shipping notifications
- Account notifications
- Receipts and invoices
- Security alerts

**Resend Implementation:**
- Send via API or SMTP
- Charged per email sent
- Free tier: 3,000/month, 100/day
- Pro: $20 for 50,000 emails

### Marketing Emails

**Definition**: Promotional messages sent to promote products, services, or content. Users **must** have ability to unsubscribe.

**Examples:**
- Newsletters
- Product announcements
- Promotional campaigns
- Weekly digests
- Sales and discounts
- Educational content

**Resend Implementation:**
- Send via **Broadcasts** feature
- WYSIWYG editor for creating campaigns
- Charged per contact, not per email sent
- Free tier: 1,000 contacts with unlimited sends
- Pro: $40 for 5,000 contacts

### Pricing Comparison

| Email Type | Free Tier | Paid Plan | Billing Model |
|------------|-----------|-----------|---------------|
| Transactional | 3,000/month | $20 for 50k | Per email sent |
| Marketing | 1,000 contacts | $40 for 5k contacts | Per contact (unlimited sends) |

---

## GDPR & Legal Compliance

### Marketing Email Legal Requirements

#### CAN-SPAM (United States)

**Requirements:**
1. **Honest Subject Lines**: No deceptive or misleading subject lines
2. **Identify as Advertisement**: Messages must be clearly identified as ads
3. **Physical Address**: Must include valid physical postal address (can be PO box)
4. **Unsubscribe Link**: Clear and conspicuous opt-out method
5. **Honor Opt-Outs**: Process unsubscribe requests within **10 business days**

**Consent Model**: Opt-out (can send to anyone until they unsubscribe)

**Penalties**: Up to **$50,000 per non-compliant email**

#### GDPR (European Union)

**Requirements:**
1. **Explicit Opt-In**: Must obtain prior consent before sending (opt-in model)
2. **Freely Given Consent**: No pre-checked boxes; must be clear affirmative action
3. **Easy Unsubscribe**: Must honor unsubscribe immediately (not 10 days like CAN-SPAM)
4. **Document Consent**: Keep records of when/how consent was obtained (6+ years)
5. **Right to Object**: Users can object to direct marketing at any time
6. **Transparency**: Clearly identify who is sending the email

**Consent Model**: Opt-in (requires explicit consent before sending)

**Penalties**: Up to **€20 million or 4% of annual global revenue** (whichever is higher)

#### CASL (Canada)

**Requirements:**
1. **Express or Implied Consent**: Must obtain consent to email Canadian recipients
2. **Document Consent**: Explain how data will be used
3. **Unsubscribe Mechanism**: Easy opt-out in every email

**Penalties**: Up to **$10 million per violation**

### Double Opt-In

**Legal Requirement?**
- Generally **not required** by GDPR or CAN-SPAM
- **Required in Germany** for German businesses
- Best practice in Switzerland, Greece, and Norway

**Benefits:**
- Ensures high-quality email list
- Removes inactive or incorrect emails
- Prevents spam trap addresses
- Provides proof of consent
- Reduces bounce rates and complaints

**Recommendation**: Implement double opt-in for all marketing emails as a best practice

### Unsubscribe Handling

#### Best Practices
1. **Single-Click Unsubscribe**: No login required
2. **Process Within 24 Hours**: GDPR requires immediate action; CAN-SPAM allows 10 days
3. **Clear Link Placement**: Easy to find, not hidden in fine print
4. **Preference Center**: Allow users to choose email frequency/types
5. **Maintain Suppression List**: Never re-send to unsubscribed users

#### Legal Requirements Summary
- **CAN-SPAM**: 10 business days to honor
- **GDPR**: Immediate (must stop sending right away)
- Both require unsubscribe link in **every marketing email**

### Transactional Email Exemptions

**Important**: Transactional emails are **exempt** from most marketing email laws:
- No unsubscribe link required
- Can send without prior consent
- Cannot include promotional content (or becomes marketing email)

**Warning**: Adding heavy promotional content to transactional emails converts them to marketing emails, requiring compliance with all marketing email laws.

### GDPR Compliance Features

#### Data Requirements
1. **Consent Records**: Document when, where, and how consent was obtained
2. **Data Retention**: Keep consent records for 6+ years
3. **Right to Access**: Users can request their data
4. **Right to Deletion**: Users can request data deletion
5. **Data Portability**: Users can export their data

#### Resend Support
- Webhook events for unsubscribes
- API for managing contact lists
- Automated suppression list management
- Audit logs for compliance documentation

---

## Bounce & Complaint Handling

### Bounce Types in Resend

Resend categorizes bounces into three main types with clear, human-readable explanations:

#### 1. Permanent Bounce (Hard Bounce)
- Recipient's mail server permanently rejected the email
- Common reasons:
  - Email address doesn't exist
  - Domain doesn't exist
  - Recipient blocked sender

**Action**: Remove from email list immediately; never resend

#### 2. Transient Bounce (Soft Bounce)
- Temporary delivery failure
- Common reasons:
  - Mailbox full
  - Email too large
  - Temporary server issues

**Action**: Retry delivery (Resend handles automatically); if persistent, remove from list

#### 3. General Bounce
- Other delivery issues
- Review specific error message for details

### Bounce Subtypes
- **MailboxFull**: Recipient's inbox is full
- **MessageTooLarge**: Email exceeds size limit
- **ContentRejected**: Content triggered spam filters
- **AttachmentRejected**: Attachment type blocked

### Complaint Handling

**Definition**: Recipient marked email as spam

**Impact on Reputation:**
- Damages sender reputation
- Can lead to account suspension
- Affects deliverability for all emails

**Required Action:**
1. Remove complainant from email list immediately
2. Never send to this address again
3. Investigate what triggered complaint
4. Review content/sending practices

### Deliverability Thresholds

Resend requires maintaining:
- **Bounce Rate**: Below 4%
- **Complaint Rate**: Under 0.08%

**Warning**: Exceeding these thresholds:
- Damages domain reputation
- Risks ESP suspension
- Can blacklist your IP/domain

### Implementing Bounce/Complaint Handling

#### Using Webhooks

Monitor these events:
- `email.bounced` - Handle hard bounces
- `email.delivery_delayed` - Track soft bounces
- `email.complained` - Remove from list immediately

Example webhook handler:
```javascript
app.post('/webhook/resend', async (req, res) => {
  const event = req.body;

  switch(event.type) {
    case 'email.bounced':
      // Remove from email list
      await removeFromList(event.data.email);
      break;

    case 'email.complained':
      // Add to suppression list
      await addToSuppressionList(event.data.email);
      break;
  }

  res.status(200).send('OK');
});
```

#### Best Practices
1. **Monitor Bounce Rates**: Track daily/weekly bounce percentages
2. **Clean Lists Regularly**: Remove bounced emails promptly
3. **Implement Suppression List**: Never send to bounced/complained addresses
4. **Double Opt-In**: Reduces invalid email addresses
5. **List Hygiene**: Periodically remove inactive subscribers

### AWS SES Recommendations
- Never retry hard bounces
- Don't send to addresses that generated complaints
- Remove bounced addresses from all future sends

---

## Webhooks & API Integration

### Overview
Webhooks are real-time HTTPS requests that notify your application when events occur, such as email delivery, bounces, or spam complaints.

### Supported Events (15 Total)

#### Email Delivery Events
1. **email.sent** - API request successful; Resend will attempt delivery
2. **email.delivered** - Successfully delivered to recipient's mail server
3. **email.delivery_delayed** - Couldn't deliver to recipient's mail server (soft bounce)
4. **email.bounced** - Permanently rejected by recipient's mail server (hard bounce)

#### Engagement Events
5. **email.opened** - Recipient opened the email (requires open tracking)
6. **email.clicked** - Recipient clicked a link (requires link tracking)

#### Complaint Events
7. **email.complained** - Recipient marked email as spam

#### Contact/List Events
8. **contact.created** - New contact added
9. **contact.updated** - Contact information changed
10. **contact.deleted** - Contact removed

### Setting Up Webhooks

#### Via Dashboard
1. Navigate to **Webhooks** in Resend dashboard
2. Click **Create Webhook**
3. Enter your endpoint URL (must be HTTPS)
4. Select events to listen for
5. Save webhook

#### Via API
```javascript
const response = await fetch('https://api.resend.com/webhooks', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${RESEND_API_KEY}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: 'https://yourdomain.com/webhook/resend',
    events: ['email.bounced', 'email.complained', 'email.delivered']
  })
});
```

### Webhook Payload

Example JSON payload:
```json
{
  "type": "email.bounced",
  "created_at": "2026-02-02T12:00:00.000Z",
  "data": {
    "email_id": "abc123",
    "from": "noreply@yourdomain.com",
    "to": "user@example.com",
    "subject": "Password Reset",
    "bounce_type": "Permanent",
    "bounce_subtype": "MailboxNotFound"
  }
}
```

### Webhook Best Practices

#### 1. Verify Webhook Signatures
- Resend signs webhooks for security
- Verify signatures to prevent spoofing
- Check documentation for signature verification

#### 2. Respond with HTTP 200
- Return HTTP 200 OK to acknowledge receipt
- Process events asynchronously if needed
- Resend will retry if no 200 response

#### 3. Handle Idempotency
- Webhooks may be delivered more than once
- Use `event.id` to deduplicate events
- Implement idempotent event processing

#### 4. Process Asynchronously
- Don't block webhook response with long operations
- Queue events for background processing
- Respond quickly to avoid timeouts

### Integration with Frameworks

#### Next.js API Route
```typescript
// app/api/webhook/resend/route.ts
export async function POST(req: Request) {
  const event = await req.json();

  // Process event asynchronously
  await processEvent(event);

  return new Response('OK', { status: 200 });
}
```

#### Express.js
```javascript
app.post('/webhook/resend', express.json(), async (req, res) => {
  const event = req.body;

  // Process event
  await handleResendEvent(event);

  res.status(200).send('OK');
});
```

---

## Email Type Decision Matrix

### Should You Send Marketing Emails with Resend?

#### YES - Use Resend for Marketing if:
- ✅ You need a unified platform for all emails
- ✅ You're sending to < 5,000 contacts (Pro plan affordable)
- ✅ You want developer-first API integration
- ✅ You value consolidated billing and metrics
- ✅ Your marketing volume is low to moderate
- ✅ You want unlimited email sends per contact

#### NO - Use Separate Service for Marketing if:
- ❌ You send high-volume marketing campaigns (>100k contacts)
- ❌ You need advanced marketing automation (drip campaigns, A/B testing)
- ❌ You want visual campaign builders and landing pages
- ❌ You need detailed marketing analytics and segmentation
- ❌ You require dedicated IP pools for marketing
- ❌ You want marketing-specific features (Mailchimp, SendGrid Marketing, etc.)

### Transactional-Only vs Mixed Approach

#### Transactional Only (Recommended for Most Projects)

**Best For:**
- SaaS applications
- E-commerce platforms
- Applications with user accounts
- Projects just starting out

**Benefits:**
- Simple setup
- Lower cost (free tier likely sufficient)
- Better deliverability (no marketing email risk)
- Easier compliance (no GDPR marketing requirements)
- Focus on critical user communications

**Use Cases:**
- Password resets
- Magic login links
- Email verification
- Order confirmations
- Account notifications
- Security alerts

#### Mixed Approach (Transactional + Marketing on Resend)

**Best For:**
- Small to medium businesses
- Developer-focused products
- Projects wanting unified email platform
- Teams comfortable with API-first tools

**Benefits:**
- Single platform for all emails
- Unified billing and domain authentication
- Consolidated metrics
- Developer-friendly API
- Unlimited marketing sends (per contact pricing)

**Risks:**
- Marketing campaigns can hurt transactional deliverability
- Requires careful stream separation
- Need to implement GDPR compliance
- More complex legal requirements

**Mitigation:**
- Use separate subdomains (mail.domain.com vs news.domain.com)
- Implement proper unsubscribe handling
- Monitor bounce/complaint rates closely
- Consider separate IP addresses for high volume

#### Separate Services (Transactional + Dedicated Marketing Platform)

**Best For:**
- High-volume senders (>100k marketing emails/month)
- Marketing-heavy businesses
- Organizations needing advanced automation
- Teams with dedicated marketing personnel

**Transactional Service Options:**
- Resend (developer-friendly, 3k free/month)
- Postmark (transactional specialist)
- SendGrid API (mature platform)
- AWS SES (lowest cost, technical setup)

**Marketing Service Options:**
- Mailchimp (beginner-friendly, visual builder)
- SendGrid Marketing (same as transactional possible)
- ConvertKit (creators and newsletters)
- Loops.so (SaaS-focused, similar to Resend)

**Benefits:**
- Complete separation of reputation
- Specialized features for each use case
- Better deliverability protection
- Advanced marketing automation
- Dedicated IP addresses

**Drawbacks:**
- Two separate platforms to manage
- Duplicate domain authentication
- Higher total cost
- Split metrics and reporting

### Decision Framework

Use this flowchart to decide:

```
1. Do you need to send marketing emails at all?
   NO → Use Resend for transactional only (simplest option)
   YES → Continue to #2

2. Will you send > 5,000 marketing emails per month?
   NO → Continue to #3
   YES → Continue to #4

3. Do you need advanced marketing features?
   (drip campaigns, A/B testing, visual builders, detailed segmentation)
   NO → Use Resend for both (unified platform)
   YES → Use separate marketing service (Mailchimp, ConvertKit)

4. Do you need advanced marketing features?
   NO → Use Resend for both (still cost-effective)
   YES → Use separate marketing service (better specialized features)

5. Is your transactional email mission-critical?
   (password resets, order confirmations, security alerts)
   YES → Consider separate services (protect deliverability)
   NO → Resend for both is fine
```

### Recommended Setups by Project Type

#### Startup / MVP
- **Transactional**: Resend (free tier)
- **Marketing**: None initially; add later if needed
- **Why**: Minimize complexity and cost; focus on product

#### Small SaaS (< 1,000 users)
- **Transactional**: Resend (free tier sufficient)
- **Marketing**: Resend Broadcasts (if needed)
- **Why**: Unified platform; free tier covers both

#### Growing SaaS (1,000-10,000 users)
- **Transactional**: Resend Pro ($20/month)
- **Marketing**: Resend Pro ($40/month) OR separate service
- **Why**: Affordable scaling; consider separation if marketing-heavy

#### Established SaaS (10,000+ users)
- **Transactional**: Resend Scale/Enterprise
- **Marketing**: Dedicated platform (Mailchimp, SendGrid Marketing)
- **Why**: Protect transactional deliverability; advanced features

#### E-commerce Platform
- **Transactional**: Resend or Postmark
- **Marketing**: Separate service (Klaviyo, Mailchimp)
- **Why**: Order emails are critical; marketing automation needed

#### Content/Creator Platform
- **Transactional**: Resend (free tier)
- **Marketing**: ConvertKit or Loops.so
- **Why**: Focus on newsletter/content features

### Legal Compliance Summary

| Email Type | CAN-SPAM | GDPR | Unsubscribe Link | Physical Address | Consent Required |
|------------|----------|------|------------------|------------------|------------------|
| Transactional | Exempt | Exempt | No | No | No |
| Marketing | Required | Required | Yes (immediate) | Yes (US) | Yes (EU opt-in) |

### Cost Comparison Examples

#### Scenario 1: Small App (500 users, 5k transactional/month, 1k marketing contacts)
- **Resend Only**: $0/month (within free tier)
- **Resend + Mailchimp**: $0 + $20 = $20/month
- **Recommendation**: Resend only

#### Scenario 2: Growing App (5k users, 50k transactional/month, 3k marketing contacts)
- **Resend Only**: $20 (transactional) + $0 (free marketing tier) = $20/month
- **Resend + Mailchimp**: $20 + $50 = $70/month
- **Recommendation**: Resend only (save $50/month)

#### Scenario 3: Established App (50k users, 500k transactional/month, 20k marketing contacts)
- **Resend Only**: $90 (Scale plan) + $80 (marketing contacts) = $170/month
- **Resend + SendGrid Marketing**: $90 + $120 = $210/month
- **Recommendation**: Depends on marketing feature needs

### Final Recommendations

#### For Your Project (Magic Login + Password Reset)

**Phase 1: Launch (Transactional Only)**
- Use Resend free tier (3,000 emails/month)
- Send only transactional emails:
  - Magic login links
  - Password reset emails
  - Account verification
  - Security notifications
- Setup single domain: `mail.yourdomain.com`
- Cost: **$0/month**

**Phase 2: Growth (Add Marketing - Optional)**
- Decide if you need marketing emails (newsletters, product updates)
- If YES and < 1,000 contacts: Use Resend Broadcasts (still free)
- If YES and > 1,000 contacts:
  - Option A: Resend Pro Marketing ($40 for 5k contacts)
  - Option B: Separate marketing service (Mailchimp, ConvertKit)
- Setup second subdomain if using Resend: `news.yourdomain.com`
- Implement GDPR compliance (unsubscribe, consent tracking)

**Phase 3: Scale (Separate Services - If Needed)**
- If transactional email becomes mission-critical (>100k/month)
- If marketing needs advanced automation
- Keep Resend for transactional
- Add dedicated marketing platform
- Use separate IP addresses and domains

---

## Quick Start Checklist

### Transactional Email Setup (Magic Login, Password Reset)

- [ ] Sign up for Resend account at [resend.com](https://resend.com/)
- [ ] Add domain to Resend dashboard
- [ ] Configure DNS records (SPF, DKIM, DMARC)
- [ ] Verify DNS records are propagated (use dns.email)
- [ ] Create API key with `sending_access` permission
- [ ] Store API key in environment variables
- [ ] Create email templates for:
  - [ ] Magic login link
  - [ ] Password reset
  - [ ] Email verification
- [ ] Publish templates in Resend dashboard
- [ ] Implement email sending in application
- [ ] Setup webhooks for bounce/complaint handling
- [ ] Test email delivery in development
- [ ] Monitor deliverability metrics

### Marketing Email Addition (Optional)

- [ ] Decide: Same service (Resend) vs separate service?
- [ ] If Resend: Add second subdomain for marketing
- [ ] If separate: Sign up for marketing platform (Mailchimp, ConvertKit, etc.)
- [ ] Implement double opt-in for email collection
- [ ] Create unsubscribe page/handler
- [ ] Add unsubscribe link to all marketing emails
- [ ] Implement preference center
- [ ] Document consent collection (GDPR compliance)
- [ ] Create suppression list for unsubscribed users
- [ ] Add physical address to email footer (CAN-SPAM)
- [ ] Setup webhook for unsubscribe events
- [ ] Test marketing email flow
- [ ] Monitor bounce and complaint rates

---

## Resources & Documentation

### Official Resend Documentation
- [Resend Homepage](https://resend.com/)
- [API Reference](https://resend.com/docs/api-reference/introduction)
- [Domain Verification](https://resend.com/docs/dashboard/domains/introduction)
- [Templates](https://resend.com/docs/dashboard/templates/introduction)
- [Webhooks](https://resend.com/docs/dashboard/webhooks/introduction)
- [Pricing](https://resend.com/pricing)

### Email Best Practices
- [Resend Email Best Practices (GitHub)](https://github.com/resend/email-best-practices)
- [Top 10 Email Deliverability Tips](https://resend.com/blog/top-10-email-deliverability-tips)
- [Email Authentication Guide](https://resend.com/blog/email-authentication-a-developers-guide)

### Legal Compliance
- [CAN-SPAM Act Compliance Guide (FTC)](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business)
- [GDPR Email Marketing Guide](https://gdpr.eu/email-encryption/)

### Tools
- [dns.email](https://dns.email) - Check DNS records
- [React Email](https://github.com/resend/react-email) - Build emails with React

---

## Summary

### Resend Strengths
- Developer-friendly API
- Generous free tier (3,000 transactional/month, 1,000 marketing contacts)
- React Email support for modern email development
- Both transactional and marketing in one platform
- Excellent documentation
- Automatic SPF/DKIM handling
- Template versioning system

### When to Choose Resend
- You're a developer or technical team
- You need transactional emails (magic login, password reset)
- You want API-first email service
- You prefer code-based email templates (React)
- You're starting small but want room to scale
- You value unified platform for all emails

### When to Choose Alternatives
- You need advanced marketing automation (Mailchimp, ConvertKit)
- You want visual drag-and-drop email builders
- You send very high volumes (AWS SES cheaper)
- You need dedicated IP addresses
- You have non-technical marketing team

### Bottom Line for Your Project
**Start with Resend for transactional emails only.** It's free, developer-friendly, and perfect for magic login and password reset flows. Add marketing capabilities later only if needed, and decide then whether to use Resend Broadcasts or a dedicated marketing platform based on your volume and feature requirements.
