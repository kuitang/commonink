package web

import (
	"net/http"
	"strings"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/auth"
)

// AppDetailData contains data for the app detail page.
type AppDetailData struct {
	PageData
	App *apps.AppMetadata
}

// HandleAppDetail handles GET /apps/{name} - shows app detail page.
func (h *WebHandler) HandleAppDetail(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	userID := auth.GetUserID(r.Context())
	appSvc := apps.NewService(userDB, userID, h.spriteToken)
	app, err := appSvc.Get(r.Context(), name)
	if err != nil {
		h.renderer.RenderError(w, http.StatusNotFound, "App not found")
		return
	}

	data := AppDetailData{
		PageData: PageData{
			Title: app.Name,
			User:  getUserWithEmail(r),
		},
		App: app,
	}

	if err := h.renderer.Render(w, "apps/detail.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}
