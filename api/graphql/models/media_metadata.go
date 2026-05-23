package models

import "time"

// MediaMetadata is sidecar-derived "where did this picture come from" data:
// the artwork URL, author, tags, caption, etc. Today the parser understands
// gallery-dl's "{file}.json" sidecars; the schema is extractor-agnostic so
// other tools (twitter-media-downloader, yt-dlp metadata, manual XMP exports)
// can plug in later by populating the same fields.
type MediaMetadata struct {
	Model
	MediaID int   `gorm:"not null;uniqueIndex"`
	Media   Media `gorm:"constraint:OnDelete:CASCADE;"`

	// Source identifies the extractor/site, e.g. "pixiv", "twitter". Used by
	// the UI to render a site-aware link/badge.
	Source string `gorm:"size:64"`
	// SourceURL is the canonical URL of the original artwork.
	SourceURL string `gorm:"size:512"`
	// Author/AuthorURL identify the creator on the source site.
	Author    string `gorm:"size:256"`
	AuthorURL string `gorm:"size:512"`
	// Title and Caption come straight from the source posting.
	Title   string `gorm:"size:512"`
	Caption string `gorm:"type:text"`
	// Tags is a JSON-encoded []string. Stored encoded because we don't need
	// to filter by tag in SQL yet, and a flat string keeps the schema simple.
	Tags string `gorm:"type:text"`
	// PostDate is when the artwork was posted on the source site, not when
	// it was downloaded. May be nil if the sidecar didn't include it.
	PostDate *time.Time

	// SidecarPath / SidecarHash let the scanner detect that the sidecar
	// changed on disk and re-import without forcing a full media rebuild.
	SidecarPath string `gorm:"size:1024"`
	SidecarHash string `gorm:"size:64"`
}
