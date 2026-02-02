I am going to build a remote notes MCP server. It will be my first MicroSaaS so explain all of these from the ground up. The purpose is to enable AI users to share context (notes) between applications. In particular, you can connect it to ChatGPT and Claude WebApps, read/write context, save summaries of your conversations as notes artifacts, open it up again in a coding CLI and access your designs. You can also connect it to any other apps that use MCPs for a universal context. It's similar to notes apps like Notion, but there will only be a barebones web interface. I want the strongest MCP interface possible. I will implement in Golang. Do not write code; only write pseudocode. For each point, answer this question: "is there an official test program or test suite that runs as the client (the other side) so I can test behavior from my server? If not, how do I implement such a test client from the specification? Show me pseudocode, walking through the essential flow, no code." 


1. Built-in Tools in Claude Code and ChatGPT + Test Infrastructure
Claude Code's File Tools (Official Reference)
Claude Code has these built-in file tools that you should model your notes tools after:
ToolParametersDescriptionviewpath, view_range (optional)Read file/directory contentsstr_replacepath, old_str, new_strReplace text in filecreate_filepath, file_textCreate new file with contentinsertpath, insert_line, new_strInsert at specific lineundo_editpathRevert last edit
Synthesized Tool Definition for Your Notes Server:
pseudocodeTOOL note_view:
    parameters:
        note_id: string (required)
        section_range: [start_line, end_line] (optional)
    returns:
        content: string
        metadata: {title, created_at, updated_at, tags[]}
    
TOOL note_create:
    parameters:
        title: string (required)
        content: string (required)
        tags: string[] (optional)
    returns:
        note_id: string
        created_at: timestamp

TOOL note_update:
    parameters:
        note_id: string (required)
        old_content: string (for conflict detection)
        new_content: string (required)
    returns:
        success: boolean
        updated_at: timestamp

TOOL note_search:
    parameters:
        query: string (required)
        tags: string[] (optional)
        limit: integer (default 10)
    returns:
        results: [{note_id, title, snippet, relevance_score}]

TOOL note_list:
    parameters:
        cursor: string (optional, for pagination)
        limit: integer (default 20)
    returns:
        notes: [{note_id, title, updated_at}]
        next_cursor: string
ChatGPT Apps SDK (OpenAI) Tool Patterns
OpenAI's Apps SDK uses MCP but adds UI components. Key patterns:

Tool annotations: readOnlyHint: true/false for tool behavior hints
structuredContent: JSON returned alongside tool results
_meta: Hidden data for UI only (not visible to model)

Official MCP Test Infrastructure
Yes, there are official test programs:

MCP Conformance Test Suite (@modelcontextprotocol/conformance)

pseudocode   // Test your server
   RUN npx @modelcontextprotocol/conformance server 
       --url http://localhost:3000/mcp 
       --scenario server-initialize

   // Test all scenarios
   RUN npx @modelcontextprotocol/conformance server 
       --url http://localhost:3000/mcp
   
   // List available test scenarios
   RUN npx @modelcontextprotocol/conformance list --server

MCP Inspector (Visual testing tool)

pseudocode   RUN npx @modelcontextprotocol/inspector 
       --config mcp.json 
       --server my-notes-server
   
   // CLI mode for automation
   RUN npx @modelcontextprotocol/inspector --cli 
       node build/index.js 
       --method tools/list
Building a Substantive Test Client
For behavioral testing (does the AI actually use your tools correctly?), build a test harness:
pseudocode// Test using Claude Agent SDK
FUNCTION test_tool_invocation():
    // 1. Connect to your MCP server
    mcp_server = MCPServerStreamableHTTP(
        url: "http://localhost:8080/mcp",
        headers: {Authorization: "Bearer test_token"}
    )
    
    // 2. Create agent with MCP server
    agent = Agent(
        name: "Test Agent",
        instructions: "Use the notes tools to complete tasks",
        mcp_servers: [mcp_server],
        model_settings: {tool_choice: "required"}
    )
    
    // 3. Run test prompts
    test_cases = [
        {prompt: "Create a note titled 'Test' with content 'Hello'",
         expected_tool: "note_create",
         expected_params: {title: "Test", content: "Hello"}},
        
        {prompt: "Find my notes about project planning",
         expected_tool: "note_search",
         expected_params_contain: {query: "project planning"}},
    ]
    
    FOR each test_case IN test_cases:
        result = Runner.run(agent, test_case.prompt)
        
        // 4. Verify tool was called correctly
        ASSERT result.tool_calls CONTAINS test_case.expected_tool
        ASSERT result.tool_params MATCHES test_case.expected_params

// Test using OpenAI Agents SDK
FUNCTION test_openai_tool_invocation():
    agent = Agent(
        tools: [
            HostedMCPTool(
                server_label: "my-notes",
                server_url: "https://my-notes-server.com/mcp",
                require_approval: "never"
            )
        ]
    )
    
    result = Runner.run(agent, "List all my notes")
    
    // Verify the tool was invoked and returned valid data
    ASSERT result.final_output CONTAINS expected_note_titles
Essential Test Flow:
pseudocodeFUNCTION integration_test_flow():
    // Phase 1: Protocol Conformance
    run_mcp_conformance_tests()
    
    // Phase 2: Tool Schema Validation  
    FOR each tool IN server.list_tools():
        ASSERT tool.input_schema IS valid_json_schema
        ASSERT tool.description IS non_empty
    
    // Phase 3: Tool Behavior Testing
    test_response = server.call_tool("note_create", {
        title: "Test Note",
        content: "Test content"
    })
    ASSERT test_response.is_error == false
    ASSERT test_response.content[0].type == "text"
    
    // Phase 4: AI Integration Testing
    run_agent_tests_with_real_prompts()
    
    // Phase 5: Cross-Platform Testing
    test_with_claude_connector()
    test_with_chatgpt_connector()

2. OAuth for ChatGPT Applications
The Key Insight
ChatGPT expects YOU to be an OAuth Provider, not an OAuth client. This is the opposite of "Sign in with Google." You must implement OAuth 2.1 server endpoints.
Required OAuth Endpoints
pseudocode// 1. OAuth Authorization Server Metadata
ENDPOINT GET /.well-known/oauth-authorization-server
    RETURN {
        issuer: "https://your-domain.com",
        authorization_endpoint: "https://your-domain.com/oauth/authorize",
        token_endpoint: "https://your-domain.com/oauth/token",
        registration_endpoint: "https://your-domain.com/oauth/register",  // DCR
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],  // PKCE required
        scopes_supported: ["notes:read", "notes:write"]
    }

// 2. Protected Resource Metadata (on your MCP server)
ENDPOINT GET /.well-known/oauth-protected-resource
    RETURN {
        resource: "https://your-domain.com/mcp",
        authorization_servers: ["https://your-domain.com"],
        scopes_supported: ["notes:read", "notes:write"]
    }

// 3. Dynamic Client Registration (DCR)
ENDPOINT POST /oauth/register
    INPUT: {
        redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
        client_name: "Claude",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"]
    }
    OUTPUT: {
        client_id: generated_uuid,
        client_secret: generated_secret,
        client_id_issued_at: unix_timestamp,
        registration_access_token: token_for_management
    }

// 4. Authorization Endpoint
ENDPOINT GET /oauth/authorize
    PARAMS: client_id, redirect_uri, response_type, scope, state,
            code_challenge, code_challenge_method
    
    FLOW:
        1. Validate client_id exists
        2. Verify redirect_uri matches registered URIs
        3. Show user consent screen
        4. Generate authorization_code
        5. REDIRECT to redirect_uri?code={code}&state={state}

// 5. Token Endpoint  
ENDPOINT POST /oauth/token
    FOR grant_type == "authorization_code":
        Validate code_verifier against stored code_challenge (PKCE)
        Exchange code for access_token + refresh_token
        
    FOR grant_type == "refresh_token":
        Validate refresh_token
        Issue new access_token
    
    RETURN {
        access_token: jwt_or_opaque_token,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: "notes:read notes:write"
    }
Complete OAuth Flow
pseudocodeSEQUENCE ChatGPT_OAuth_Flow:
    1. User adds your connector in ChatGPT Settings
    2. ChatGPT fetches /.well-known/oauth-protected-resource
    3. ChatGPT discovers authorization server from metadata
    4. ChatGPT calls /oauth/register (DCR) to get client credentials
    5. ChatGPT redirects user to /oauth/authorize with PKCE
    6. User authenticates and consents
    7. Your server redirects back with authorization code
    8. ChatGPT exchanges code for tokens at /oauth/token
    9. ChatGPT stores tokens and uses them for MCP requests
    10. On token expiry, ChatGPT uses refresh_token to get new access_token
Local Testing
pseudocodeFUNCTION setup_local_testing():
    // 1. Use ngrok for public URL
    RUN ngrok http 8080
    // Returns: https://abc123.ngrok.io
    
    // 2. Configure your server with ngrok URL
    server_config.base_url = "https://abc123.ngrok.io"
    
    // 3. Test with MCP Inspector first
    RUN npx @modelcontextprotocol/inspector
    // Enter your ngrok URL
    // Click "Open Auth Settings" → "Quick OAuth Flow"
    // Walk through each OAuth step
    
    // 4. Test with ChatGPT Developer Mode
    // Settings → Connectors → Developer Mode (enable)
    // Create connector with ngrok URL + /mcp
    
    // 5. Debug common issues:
    CHECK_CORS_HEADERS()  // Must allow ChatGPT origins
    CHECK_REDIRECT_URI_MATCHES()
    CHECK_PKCE_IMPLEMENTATION()
Test Client for OAuth (Pseudocode)
pseudocodeFUNCTION test_oauth_flow():
    // Simulates what ChatGPT does
    
    // Step 1: Discover metadata
    metadata = HTTP_GET("/.well-known/oauth-authorization-server")
    ASSERT metadata.authorization_endpoint EXISTS
    
    // Step 2: Dynamic registration
    dcr_response = HTTP_POST(metadata.registration_endpoint, {
        redirect_uris: ["http://localhost:3000/callback"],
        client_name: "Test Client"
    })
    ASSERT dcr_response.client_id EXISTS
    
    // Step 3: Generate PKCE
    code_verifier = random_string(64)
    code_challenge = base64url(sha256(code_verifier))
    
    // Step 4: Start authorization
    auth_url = metadata.authorization_endpoint + "?" + urlencode({
        client_id: dcr_response.client_id,
        redirect_uri: "http://localhost:3000/callback",
        response_type: "code",
        scope: "notes:read notes:write",
        state: random_string(32),
        code_challenge: code_challenge,
        code_challenge_method: "S256"
    })
    
    // Step 5: Manual browser auth or headless
    code = get_code_from_redirect()
    
    // Step 6: Token exchange
    token_response = HTTP_POST(metadata.token_endpoint, {
        grant_type: "authorization_code",
        client_id: dcr_response.client_id,
        client_secret: dcr_response.client_secret,
        code: code,
        redirect_uri: "http://localhost:3000/callback",
        code_verifier: code_verifier
    })
    
    ASSERT token_response.access_token EXISTS
    
    // Step 7: Test MCP with token
    mcp_response = HTTP_POST("/mcp", {
        headers: {Authorization: "Bearer " + token_response.access_token},
        body: {method: "tools/list"}
    })
    ASSERT mcp_response.tools IS NOT empty


How Claude Connectors Work
pseudocodeSEQUENCE Claude_Connector_Flow:
    // For Individual Pro/Max users:
    1. User goes to Settings → Connectors
    2. User clicks "Add custom connector"
    3. User enters MCP server URL
    4. (Optional) User enters custom Client ID/Secret in Advanced Settings
    
    // If OAuth enabled:
    5. Claude fetches /.well-known/oauth-protected-resource
    6. Claude performs DCR (or uses provided client_id/secret)
    7. Claude redirects user to authorize
    8. User authenticates on YOUR server
    9. Redirect back to claude.ai/api/mcp/auth_callback
    10. Claude exchanges code for tokens
    
    // For Team/Enterprise:
    - Only Owners can ADD connectors
    - Users individually CONNECT to added connectors
    - This ensures users only access data they're authorized for
Claude-Specific Implementation Notes
pseudocode// Claude's callback URLs (whitelist BOTH)
ALLOWED_REDIRECT_URIS = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback"  // Future
]

// Claude's OAuth client name
IF request.client_name == "Claude":
    // This is Claude connecting

// Claude supports authless servers
// If no OAuth needed, just serve MCP directly:
ENDPOINT POST /mcp
    IF requires_auth AND no_valid_token:
        RETURN 401 with WWW-Authenticate header
    ELSE:
        process_mcp_request()
```

### Registering a Claude Connector

**For your service/SaaS:**
1. Deploy your MCP server with OAuth endpoints
2. Test with MCP Inspector
3. Document for users: "Add custom connector with URL: https://your-domain.com/mcp"

**No formal "registration" process** like app stores. Users add your URL directly.

---

pseudocode// OAuth 2.0 Flow (you're the CLIENT here)
SEQUENCE OAuth2_Authorization_Code_Flow:
    1. User clicks "Sign in with Google"
    2. Redirect to Google: accounts.google.com/o/oauth2/auth?
        client_id=YOUR_CLIENT_ID
        redirect_uri=https://your-app.com/callback
        response_type=code
        scope=openid email profile
        state=random_csrf_token
    3. User logs into Google, consents
    4. Google redirects: your-app.com/callback?code=AUTH_CODE&state=...
    5. Your server exchanges code for tokens:
        POST https://oauth2.googleapis.com/token
        {client_id, client_secret, code, redirect_uri, grant_type=authorization_code}
    6. Google returns: {access_token, refresh_token, id_token, expires_in}
    
    
    
// ID Token is a JWT with structure:
ID_TOKEN = {
    header: {alg: "RS256", kid: "google_key_id"},
    payload: {
        iss: "https://accounts.google.com",  // Issuer
        sub: "1234567890",                    // Unique user ID
        email: "user@gmail.com",
        email_verified: true,
        name: "John Doe",
        picture: "https://...",
        aud: "YOUR_CLIENT_ID",                // Audience (your app)
        iat: 1234567890,                      // Issued at
        exp: 1234571490                       // Expires
    },
    signature: "..."                          // Cryptographic signature
}

// Validate ID Token:
FUNCTION validate_id_token(token):
    1. Decode JWT
    2. Verify signature using Google's public keys (JWKS)
    3. Check iss == "https://accounts.google.com"
    4. Check aud == YOUR_CLIENT_ID
    5. Check exp > current_time
    6. Extract sub as unique user identifier
```

### Your Dual Role
```
┌─────────────────────────────────────────────────────────────┐
│                     YOUR NOTES APP                          │
├──────────────────────────┬──────────────────────────────────┤
│    OAuth CLIENT          │     OAuth PROVIDER               │
│    (for Google Sign-In)  │     (for ChatGPT/Claude)         │
├──────────────────────────┼──────────────────────────────────┤
│ You request ID token     │ You issue access tokens          │
│ from Google              │ to AI clients                    │
│                          │                                  │
│ Google authenticates     │ You authenticate users           │
│ users for you            │ (via Google Sign-In)             │
│                          │                                  │
│ You receive user info    │ ChatGPT receives access          │
│ (email, name, sub)       │ to user's notes                  │
└──────────────────────────┴──────────────────────────────────┘


// User signs in with Google, then uses your app via ChatGPT:

1. User visits your-notes-app.com
2. User clicks "Sign in with Google"
3. Google OIDC flow:
   - User authenticates with Google
   - Your app receives ID token + access token
   - You create/lookup user by Google `sub` claim
   - You create a session (cookie or your own JWT)

4. User connects your app to ChatGPT:
   - ChatGPT calls your OAuth endpoints (you're provider now)
   - Your /oauth/authorize shows consent screen
   - User is already logged in (via Google session)
   - You issue YOUR access token to ChatGPT
   - ChatGPT uses YOUR token for MCP requests

5. On MCP request:
   - ChatGPT sends: Authorization: Bearer <YOUR_TOKEN>
   - You validate YOUR token
   - You identify which user this token belongs to
   - You return that user's notes
```

---

// Installation (Community SDK)
GO_GET github.com/NdoleStudio/lemonsqueezy-go

// Initialize
client = lemonsqueezy.New(lemonsqueezy.WithAPIKey("..."))

// Create checkout URL
FUNCTION create_checkout(user_id, variant_id):
    checkout, _, err = client.Checkouts.Create(ctx, 
        store_id,
        variant_id,  // Your product variant
        {
            CustomPrice: nil,
            ProductOptions: {
                RedirectURL: "https://your-app.com/success",
            },
            CheckoutData: {
                Email: user.Email,
                Custom: {"user_id": user_id}
            }
        }
    )
    RETURN checkout.Data.Attributes.URL

// Handle webhooks
FUNCTION handle_lemon_webhook(request):
    event_name = request.headers["X-Event-Name"]
    signature = request.headers["X-Signature"]
    
    // Verify signature
    IF NOT verify_hmac(request.body, signature, webhook_secret):
        RETURN 401
    
    payload = json.parse(request.body)
    
    SWITCH event_name:
        CASE "subscription_created":
            // New subscription
            user_id = payload.meta.custom_data.user_id
            ACTIVATE_SUBSCRIPTION(user_id, payload.data)
            
        CASE "subscription_updated":
            UPDATE_SUBSCRIPTION(payload.data)
            
        CASE "subscription_cancelled":
            DEACTIVATE_SUBSCRIPTION(payload.data)
            
        CASE "order_created":
            // One-time purchase
            FULFILL_ORDER(payload.data)
            
            
FUNCTION setup_payment_testing():
    // Stripe test mode
    1. Use sk_test_... and pk_test_... keys
    2. Use test card numbers:
       - Success: 4242424242424242
       - Decline: 4000000000000002
       - 3D Secure: 4000002500003155
    3. Use Stripe CLI for webhooks:
       RUN stripe listen --forward-to localhost:8080/webhooks/stripe
       // Gives you webhook signing secret
    
    // LemonSqueezy test mode
    1. Create test mode API key
    2. Use test store
    3. Use RequestBin or ngrok for webhook testing
    
    // Integration test pseudocode
    FUNCTION test_subscription_lifecycle():
        // 1. Create checkout
        session = create_checkout("test_user", "premium_plan")
        
        // 2. Simulate successful payment (Stripe CLI)
        RUN stripe trigger checkout.session.completed
        
        // 3. Verify user activated
        user = db.get_user("test_user")
        ASSERT user.subscription_status == "active"
        
        // 4. Simulate cancellation
        RUN stripe trigger customer.subscription.deleted
        
        // 5. Verify user deactivated
        user = db.get_user("test_user")
        ASSERT user.subscription_status == "cancelled"
        
        
PRIVACY_POLICY = {
    1. DATA_COLLECTED: {
        // Be specific:
        - Account data: email, name (from Google Sign-In)
        - Content data: notes, titles, tags (user-created)
        - Usage data: access logs, feature usage
        - Payment data: billing info (processed by Stripe, not stored by you)
    },
    
    2. LEGAL_BASIS: {
        // GDPR requires one of:
        - Consent: user explicitly agreed
        - Contract: necessary to provide service
        - Legitimate Interest: reasonable business purpose
    },
    
    3. DATA_USAGE: {
        - Providing the notes service
        - Authentication
        - Billing
        - Service improvement (anonymized analytics)
    },
    
    4. DATA_SHARING: {
        - Stripe (payment processing)
        - Google (authentication)
        - Claude/ChatGPT (when user connects their account)
        - NO selling to third parties
    },
    
    5. USER_RIGHTS: {
        // Required by GDPR, CCPA:
        - Access: request a copy of their data
        - Rectification: correct inaccurate data
        - Deletion: "right to be forgotten"
        - Portability: export in machine-readable format
        - Object: stop processing their data
    },
    
    6. DATA_RETENTION: {
        - Active accounts: as long as account exists
        - After deletion: removed within 30 days
        - Backups: purged within 90 days
    },
    
    7. SECURITY_MEASURES: {
        - Encryption at rest (AES-256)
        - Encryption in transit (TLS 1.3)
        - Access controls (role-based)
        - Regular security audits
    },
    
    8. CONTACT: {
        - Data protection officer (if >250 employees or large-scale processing)
        - Email for privacy inquiries
    }
}

CONNECTOR_TERMS = {
    disclosure: "When you connect this service to AI assistants 
                 (Claude, ChatGPT), those platforms can access 
                 your notes based on your conversation.",
    
    data_flow: "Your notes content may be processed by:
                - Anthropic (Claude) - per their privacy policy
                - OpenAI (ChatGPT) - per their privacy policy
                You remain the data controller.",
    
    consent: "By connecting this service to AI assistants, 
              you consent to your notes being accessed as 
              described above."
}

GOOGLE_SIGNIN_TERMS = {
    data_received: "We receive: email, name, profile picture 
                    from Google.",
    usage: "Used solely for authentication and account creation.",
    no_google_api_access: "We do not access your Google Drive, 
                           Gmail, or other Google services."
}

SECURITY_REQUIREMENTS = {
    separate_database: {
        what_it_provides: [
            "Logical isolation",
            "Easier per-user backup/deletion",
            "Clear data boundaries"
        ],
        what_it_does_not_provide: [
            "Protection if server compromised",
            "Protection from DB dump theft",
            "Compliance checkbox for encryption"
        ]
    },
    
    what_you_actually_need: {
        encryption_at_rest: {
            implementation: [
                "Database-level encryption (PostgreSQL TDE)",
                "Disk-level encryption (LUKS, AWS EBS encryption)",
                "Cloud provider encryption (enabled by default on AWS RDS)"
            ],
            key_management: "Use AWS KMS, Google Cloud KMS, or HashiCorp Vault"
        },
        
        encryption_in_transit: {
            implementation: "TLS 1.2+ for all connections",
            internal: "Encrypt DB connections too, not just client-facing"
        },
        
        application_level_encryption: {
            consideration: "For highly sensitive data, encrypt BEFORE storing",
            example: "note.encrypted_content = AES_encrypt(content, user_key)",
            key_derivation: "Derive from user's auth, so you can't decrypt without them"
        }
    }
}

LIABILITY_PROTECTION = {
    1. LIMITATION_OF_LIABILITY: {
        clause: "Our liability is limited to the amount you paid 
                 us in the past 12 months.",
        types: "We are not liable for indirect, incidental, 
                consequential damages."
    },
    
    2. INDEMNIFICATION: {
        clause: "You agree to indemnify us against claims arising 
                 from your use of the service, including content 
                 you store."
    },
    
    3. WARRANTY_DISCLAIMER: {
        clause: "Service provided 'as is'. We don't guarantee 
                 uninterrupted service or that it meets your 
                 specific requirements."
    },
    
    4. DATA_PROCESSING_AGREEMENT: {
        when: "Required when enterprise customers process EU 
               personal data through your service",
        contents: [
            "Data processing instructions",
            "Security measures",
            "Subprocessor list",
            "Data breach notification procedures",
            "Audit rights"
        ]
    },
    
    5. INSURANCE: {
        consider: [
            "Cyber liability insurance",
            "Errors & omissions insurance",
            "General liability insurance"
        ]
    }
}

COMPLIANCE_CHECKLIST = {
    legal_docs: [
        "[ ] Privacy Policy published and linked from sign-up",
        "[ ] Terms of Service with limitation of liability",
        "[ ] Cookie notice if using analytics",
        "[ ] DPA template for enterprise customers"
    ],
    
    technical: [
        "[ ] TLS everywhere (no http)",
        "[ ] Database encryption at rest enabled",
        "[ ] Password hashing (bcrypt, argon2)",
        "[ ] Access logging",
        "[ ] Regular backups with encryption",
        "[ ] Data deletion endpoint working"
    ],
    
    operational: [
        "[ ] Process for handling data subject requests",
        "[ ] Data breach response plan",
        "[ ] Subprocessor list maintained",
        "[ ] Employee security training"
    ],
    
    gdpr_specific: [
        "[ ] Legal basis documented for each processing activity",
        "[ ] Consent mechanism with clear opt-in",
        "[ ] Data portability export function",
        "[ ] Right to deletion implementation"
    ]
}


3. Do Claude and ChatGPT Use the SAME OAuth Flow?
Short answer: Yes, fundamentally the same — both use OAuth 2.1 + PKCE + Dynamic Client Registration.

# encryption
- one sqllite db per user
- deployment: fly.io
- sqlcipher + derived KEK + 
- 
┌─────────────────────────────────────────────────────────────────┐
│  VERSIONED DERIVED KEKs                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEK = HKDF(master_key, user_id + ":" + version)                 │
│                                                                   │
│  user_keys (                                                      │
│      user_id        TEXT,                                         │
│      kek_version    INT,      -- Increment to rotate KEK         │
│      encrypted_dek  BLOB,                                         │
│  )                                                                │
│                                                                   │
│  To rotate user's KEK:                                            │
│  1. Derive old KEK with old version                              │
│  2. Decrypt DEK                                                   │
│  3. Increment version                                             │
│  4. Derive new KEK with new version                              │
│  5. Re-encrypt DEK with new KEK                                  │
│  6. Update database                                               │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘

master key stored in fly secrets.

# email
- use resend

# other considerations
- ratelimit
- fts search using sqllite -- design the mcp interface. search both title and content.
- 
