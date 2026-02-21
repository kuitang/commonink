// Package browser contains Playwright E2E tests for browser-based UI flows.
// These are deterministic scenario-based tests (NOT property-based).
//
// This file tests Notes CRUD operations via the web UI.
//
// Prerequisites:
// - Install Playwright browsers: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
// - Run tests with: go test -v ./tests/browser/...
package browser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// =============================================================================
// Test: Create
// =============================================================================

func TestBrowser_NotesCRUD_CreateNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-create")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /notes/new
	Navigate(t, page, env.BaseURL, "/notes/new")

	// Wait for the form to be visible
	titleInput := WaitForSelector(t, page, "input#title")
	contentTextarea := WaitForSelector(t, page, "textarea#content")

	// Fill in the form
	err = titleInput.Fill("Test Note from Playwright")
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("This is test content created by Playwright E2E test.\n\n**Bold text** and *italic text*.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	// Click the submit button
	submitButton := page.Locator("button[type='submit']:has-text('Create')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for redirect to the note view page
	err = page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect after create: %v", err)
	}

	// Verify the note title is displayed
	titleElement := WaitForSelector(t, page, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != "Test Note from Playwright" {
		t.Errorf("Expected title 'Test Note from Playwright', got '%s'", titleText)
	}
}

// =============================================================================
// Test: Read Note (View Note)
// =============================================================================

func TestBrowser_NotesCRUD_ReadNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-read")
	env.LoginUser(t, ctx, testEmail)

	// First create a note
	Navigate(t, page, env.BaseURL, "/notes/new")

	titleInput := WaitForSelector(t, page, "input#title")
	contentTextarea := WaitForSelector(t, page, "textarea#content")

	err = titleInput.Fill("Note for Reading Test")
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("Content for the reading test note.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := page.Locator("button[type='submit']:has-text('Create')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for redirect to note view
	err = page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect: %v", err)
	}

	// Navigate to notes list
	Navigate(t, page, env.BaseURL, "/notes")

	// Wait for the notes list to load
	WaitForSelector(t, page, "h1:has-text('My Notes')")

	// Click on the note in the list
	noteLink := page.Locator("article a:has-text('Note for Reading Test')")
	err = noteLink.Click()
	if err != nil {
		t.Fatalf("Failed to click on note: %v", err)
	}

	// Wait for the note view page
	err = page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for note view: %v", err)
	}

	// Verify title is displayed
	titleElement := WaitForSelector(t, page, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != "Note for Reading Test" {
		t.Errorf("Expected title 'Note for Reading Test', got '%s'", titleText)
	}

	// Verify content is displayed
	contentElement := page.Locator(".prose")
	contentText, err := contentElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get content text: %v", err)
	}

	if contentText == "" {
		t.Error("Expected note content to be displayed")
	}
}

// =============================================================================
// Test: Update Note (Edit Note)
// =============================================================================

func TestBrowser_NotesCRUD_EditNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-edit")
	env.LoginUser(t, ctx, testEmail)

	// First create a note
	Navigate(t, page, env.BaseURL, "/notes/new")

	titleInput := WaitForSelector(t, page, "input#title")
	contentTextarea := WaitForSelector(t, page, "textarea#content")

	err = titleInput.Fill("Original Title")
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("Original content before editing.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := page.Locator("button[type='submit']:has-text('Create')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for redirect to note view
	err = page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect: %v", err)
	}

	// Click the Edit Note button
	editButton := WaitForSelector(t, page, "a:has-text('Edit Note')")
	err = editButton.Click()
	if err != nil {
		t.Fatalf("Failed to click edit button: %v", err)
	}

	// Wait for edit page to load
	err = page.WaitForURL("**/edit", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for edit page: %v", err)
	}

	// Clear and update the title
	titleInput = WaitForSelector(t, page, "input#title")
	err = titleInput.Fill("")
	if err != nil {
		t.Fatalf("Failed to clear title: %v", err)
	}
	err = titleInput.Fill("Updated Title")
	if err != nil {
		t.Fatalf("Failed to fill new title: %v", err)
	}

	// Clear and update the content
	contentTextarea = WaitForSelector(t, page, "textarea#content")
	err = contentTextarea.Fill("")
	if err != nil {
		t.Fatalf("Failed to clear content: %v", err)
	}
	err = contentTextarea.Fill("Updated content after editing.")
	if err != nil {
		t.Fatalf("Failed to fill new content: %v", err)
	}

	// Click Save
	saveButton := page.Locator("button[type='submit']:has-text('Save')")
	err = saveButton.Click()
	if err != nil {
		t.Fatalf("Failed to click save button: %v", err)
	}

	// Wait for redirect back to note view
	err = page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect after save: %v", err)
	}

	// Verify the updated title is displayed
	titleElement := WaitForSelector(t, page, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != "Updated Title" {
		t.Errorf("Expected title 'Updated Title', got '%s'", titleText)
	}
}

// =============================================================================
// Test: Delete Note
// =============================================================================

func TestBrowser_NotesCRUD_DeleteNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-delete")
	env.LoginUser(t, ctx, testEmail)

	// First create a note
	Navigate(t, page, env.BaseURL, "/notes/new")

	titleInput := WaitForSelector(t, page, "input#title")
	contentTextarea := WaitForSelector(t, page, "textarea#content")

	noteTitle := "Note to Delete"
	err = titleInput.Fill(noteTitle)
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("This note will be deleted.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := page.Locator("button[type='submit']:has-text('Create')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for redirect to note view
	err = page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect: %v", err)
	}

	// Set up dialog handler for confirmation
	page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click the Delete button
	deleteButton := WaitForSelector(t, page, "button:has-text('Delete')")
	err = deleteButton.Click()
	if err != nil {
		t.Fatalf("Failed to click delete button: %v", err)
	}

	// Wait for redirect to notes list
	err = page.WaitForURL("**/notes", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect after delete: %v", err)
	}

	// Verify the note is no longer in the list
	noteLink := page.Locator(fmt.Sprintf("article a:has-text('%s')", noteTitle))
	count, err := noteLink.Count()
	if err != nil {
		t.Fatalf("Failed to count note links: %v", err)
	}

	if count > 0 {
		t.Error("Deleted note should not appear in the list")
	}
}

// =============================================================================
// Test: Notes List Pagination
// =============================================================================

func TestBrowser_NotesCRUD_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-pagination")
	env.LoginUser(t, ctx, testEmail)

	// Use UI-only note creation for pagination coverage.
	// Notes page size is 12; 13 is the minimum count that produces page 2.
	for i := 1; i <= 13; i++ {
		CreateNoteViaUI(
			t,
			page,
			env.BaseURL,
			fmt.Sprintf("Pagination Test Note %02d", i),
			fmt.Sprintf("Content for pagination test note %d", i),
		)
	}

	// Set desktop viewport to ensure pagination buttons are visible
	page.SetViewportSize(1280, 800)

	// Navigate to notes list
	Navigate(t, page, env.BaseURL, "/notes")

	// Wait for page to load
	WaitForSelector(t, page, "h1:has-text('My Notes')")

	// Verify pagination is shown
	paginationNav := page.Locator("nav[aria-label='Pagination']")
	err = paginationNav.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		// Debug: show page content
		content, _ := page.Content()
		if len(content) > 1000 {
			content = content[:1000] + "..."
		}
		t.Fatalf("Pagination should be visible with 13 notes. Page content: %s", content)
	}

	// Click "Next" to go to page 2 - target the visible desktop button
	nextButton := page.Locator("nav[aria-label='Pagination'] nav a[href*='page=2']")

	err = nextButton.First().Click()
	if err != nil {
		t.Fatalf("Failed to click next button: %v", err)
	}

	// Wait for page 2 to load by waiting for previous button to be visible
	prevButton := page.Locator("nav[aria-label='Pagination'] nav a[href*='page=1']")
	err = prevButton.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		currentURL := page.URL()
		t.Fatalf("Failed to navigate to page 2 - prev button not visible. Current URL: %s, error: %v", currentURL, err)
	}

	// Verify we're actually on page 2
	currentURL := page.URL()
	if !strings.Contains(currentURL, "page=2") {
		t.Errorf("Expected URL to contain 'page=2', got: %s", currentURL)
	}
}

// =============================================================================
// Test: Empty State
// =============================================================================

func TestBrowser_NotesCRUD_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	// Use a unique email to ensure this is a fresh user with no notes
	testEmail := GenerateUniqueEmail("test-empty")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to notes list
	Navigate(t, page, env.BaseURL, "/notes")

	// Wait for page to load
	WaitForSelector(t, page, "h1:has-text('My Notes')")

	// Verify "No notes yet" message is displayed
	emptyMessage := page.Locator("h3:has-text('No notes yet')")
	count, err := emptyMessage.Count()
	if err != nil {
		t.Fatalf("Failed to check empty message: %v", err)
	}

	if count == 0 {
		t.Error("Expected 'No notes yet' message for new user")
	}

	// Verify "Create your first note" button is displayed
	createButton := page.Locator("a:has-text('Create your first note')")
	count, err = createButton.Count()
	if err != nil {
		t.Fatalf("Failed to check create button: %v", err)
	}

	if count == 0 {
		t.Error("Expected 'Create your first note' button in empty state")
	}

	// Click the "Create your first note" button
	err = createButton.Click()
	if err != nil {
		t.Fatalf("Failed to click create button: %v", err)
	}

	// Verify redirect to /notes/new
	err = page.WaitForURL("**/notes/new", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to new note page: %v", err)
	}

	// Verify the new note form is displayed
	WaitForSelector(t, page, "input#title")
	WaitForSelector(t, page, "textarea#content")
}

// =============================================================================
// Test: New Note Button from List View
// =============================================================================

func TestBrowser_NotesCRUD_NewNoteButton(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-new-button")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to notes list
	Navigate(t, page, env.BaseURL, "/notes")

	// Wait for page to load
	WaitForSelector(t, page, "h1:has-text('My Notes')")

	// Click "New Note" button in the header
	newNoteButton := page.Locator("a:has-text('New Note')")
	err = newNoteButton.Click()
	if err != nil {
		t.Fatalf("Failed to click New Note button: %v", err)
	}

	// Verify redirect to /notes/new
	err = page.WaitForURL("**/notes/new", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to new note page: %v", err)
	}

	// Verify the new note form is displayed with proper heading
	heading := WaitForSelector(t, page, "h1:has-text('Create New Note')")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}

	if !strings.Contains(headingText, "Create New Note") {
		t.Errorf("Expected heading 'Create New Note', got '%s'", headingText)
	}
}

// =============================================================================
// Test: Ctrl+Enter saves note (regression test for shortcut targeting wrong form)
// =============================================================================

func TestCtrlEnter_SavesNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	env.InitBrowser(t)
	ctx := env.NewContext(t)
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()

	testEmail := GenerateUniqueEmail("test-ctrlenter")
	env.LoginUser(t, ctx, testEmail)

	// Navigate to /notes/new
	Navigate(t, page, env.BaseURL, "/notes/new")

	// Wait for the form to be visible
	titleInput := WaitForSelector(t, page, "input#title")
	contentTextarea := WaitForSelector(t, page, "textarea#content")

	// Fill in the form
	noteTitle := "Ctrl+Enter Test Note"
	err = titleInput.Fill(noteTitle)
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("Content saved via Ctrl+Enter keyboard shortcut.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	// Press Ctrl+Enter and wait for the navigation it triggers
	_, err = page.ExpectNavigation(func() error {
		return page.Keyboard().Press("Control+Enter")
	}, playwright.PageExpectNavigationOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		currentURL := page.URL()
		t.Fatalf("Ctrl+Enter did not trigger navigation. Current URL: %s, error: %v", currentURL, err)
	}

	// Verify the URL is NOT the homepage and NOT the new note page
	currentURL := page.URL()
	if strings.HasSuffix(currentURL, "/") {
		t.Fatalf("Ctrl+Enter redirected to homepage instead of saving the note. URL: %s", currentURL)
	}
	if strings.HasSuffix(currentURL, "/notes/new") {
		t.Fatalf("Ctrl+Enter did not submit the form, still on /notes/new. URL: %s", currentURL)
	}
	if strings.HasSuffix(currentURL, "/login") {
		t.Fatalf("Ctrl+Enter triggered logout instead of saving the note. URL: %s", currentURL)
	}

	// Verify the note title is displayed on the view page
	titleElement := WaitForSelector(t, page, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != noteTitle {
		t.Errorf("Expected title %q, got %q", noteTitle, strings.TrimSpace(titleText))
	}
}
