package browser

import root "github.com/kuitang/agent-notes/tests/browser"

type BrowserTestEnv = root.BrowserTestEnv

const (
	browserMaxTimeoutMS = root.BrowserMaxTimeoutMS
	browserMaxTimeout   = root.BrowserMaxTimeout
)

var (
	SetupBrowserTestEnv   = root.SetupBrowserTestEnv
	Navigate              = root.Navigate
	WaitForSelector       = root.WaitForSelector
	CreateNoteViaUI       = root.CreateNoteViaUI
	PublishNoteViaUI      = root.PublishNoteViaUI
	GenerateUniqueEmail   = root.GenerateUniqueEmail
	GenerateUniqueAppName = root.GenerateUniqueAppName
	testFirstServiceName  = root.TestFirstServiceName
	BuildTestSSEEventBody = root.TestSSEEventBody
)
