package scanner_tasks

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/photoview/photoview/api/graphql/models"
	"github.com/photoview/photoview/api/log"
	"github.com/photoview/photoview/api/scanner/scanner_task"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MetadataSidecarTask reads a "{media}.json" sidecar (the format written by
// gallery-dl, yt-dlp's --write-info-json, etc.) and persists the source-site
// metadata (author, URL, tags, caption) into MediaMetadata.
//
// The task runs once on AfterMediaFound. If the sidecar changes on disk later
// it'll be re-imported on the next scan because we store a content hash.
type MetadataSidecarTask struct {
	scanner_task.ScannerTaskBase
}

func (t MetadataSidecarTask) AfterMediaFound(ctx scanner_task.TaskContext, media *models.Media, newMedia bool) error {
	sidecarPath := media.Path + ".json"
	info, err := os.Stat(sidecarPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		log.Warn(ctx, "metadata sidecar stat failed", "path", sidecarPath, "error", err)
		return nil
	}
	if info.IsDir() {
		return nil
	}

	hash, err := hashFile(sidecarPath)
	if err != nil {
		log.Warn(ctx, "hash metadata sidecar failed", "path", sidecarPath, "error", err)
		return nil
	}

	db := ctx.GetDB()
	var existing models.MediaMetadata
	lookupErr := db.Where("media_id = ?", media.ID).First(&existing).Error
	if lookupErr == nil && existing.SidecarHash == hash {
		return nil // unchanged
	}
	if lookupErr != nil && !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
		return errors.Wrap(lookupErr, "lookup existing media metadata")
	}

	parsed, err := parseSidecarJSON(sidecarPath)
	if err != nil {
		log.Warn(ctx, "parse metadata sidecar failed", "path", sidecarPath, "error", err)
		return nil
	}

	parsed.MediaID = media.ID
	parsed.SidecarPath = sidecarPath
	parsed.SidecarHash = hash

	// Upsert: preserve id if the row already exists. Conflict on media_id
	// (which is uniquely indexed) so we just overwrite the fields.
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "media_id"}},
		UpdateAll: true,
	}).Create(parsed).Error; err != nil {
		return errors.Wrap(err, "upsert media metadata")
	}

	log.Info(ctx, "imported metadata sidecar",
		"media", media.Path, "source", parsed.Source, "author", parsed.Author)
	return nil
}

// sidecarRaw mirrors the gallery-dl JSON layout for the fields we care about.
// gallery-dl writes one JSON per downloaded file; the shape varies slightly
// per extractor but the keys below are stable across pixiv/twitter/danbooru.
type sidecarRaw struct {
	Category    string          `json:"category"`
	Subcategory string          `json:"subcategory"`
	ID          json.Number     `json:"id"`
	IllustID    json.Number     `json:"illust_id"`
	WorkID      json.Number     `json:"work_id"`
	TweetID     json.Number     `json:"tweet_id"`
	PostID      json.Number     `json:"post_id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Caption     string          `json:"caption"`
	Content     string          `json:"content"`
	Date        string          `json:"date"`
	CreateDate  string          `json:"create_date"`
	Tags        json.RawMessage `json:"tags"`
	User        struct {
		Name    string `json:"name"`
		Account string `json:"account"`
		ID      any    `json:"id"`
	} `json:"user"`
	Author struct {
		Name string `json:"name"`
	} `json:"author"`
}

func parseSidecarJSON(path string) (*models.MediaMetadata, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read sidecar")
	}

	var raw sidecarRaw
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, errors.Wrap(err, "decode sidecar")
	}

	m := &models.MediaMetadata{
		Source:  raw.Category,
		Title:   strings.TrimSpace(raw.Title),
		Caption: pickFirstNonEmpty(raw.Caption, raw.Description, raw.Content),
		Author:  pickFirstNonEmpty(raw.User.Name, raw.Author.Name),
	}

	// Derive author URL + source URL where the extractor convention is well known.
	switch raw.Category {
	case "pixiv":
		if id := pickFirstNumber(raw.ID, raw.IllustID, raw.WorkID); id != "" {
			m.SourceURL = "https://www.pixiv.net/artworks/" + id
		}
		if raw.User.Account != "" {
			m.AuthorURL = "https://www.pixiv.net/users/" + fmt.Sprint(raw.User.ID)
		}
	case "twitter":
		if raw.User.Account != "" {
			m.AuthorURL = "https://twitter.com/" + raw.User.Account
			if id := pickFirstNumber(raw.TweetID, raw.ID); id != "" {
				m.SourceURL = m.AuthorURL + "/status/" + id
			}
		}
	}

	if tags := decodeTags(raw.Tags); len(tags) > 0 {
		// Re-encode as a canonical JSON array so the column is stable.
		if encoded, err := json.Marshal(tags); err == nil {
			m.Tags = string(encoded)
		}
	}

	if d := parseSidecarDate(raw.CreateDate, raw.Date); d != nil {
		m.PostDate = d
	}

	return m, nil
}

// decodeTags handles gallery-dl's two tag representations: a plain []string
// (most extractors) or a []{name,...} (pixiv).
func decodeTags(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}

	var asStrings []string
	if err := json.Unmarshal(raw, &asStrings); err == nil {
		return cleanTagList(asStrings)
	}

	var asObjects []map[string]any
	if err := json.Unmarshal(raw, &asObjects); err == nil {
		tags := make([]string, 0, len(asObjects))
		for _, obj := range asObjects {
			if name, ok := obj["name"].(string); ok && name != "" {
				tags = append(tags, name)
			}
		}
		return cleanTagList(tags)
	}

	return nil
}

func cleanTagList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func pickFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func pickFirstNumber(values ...json.Number) string {
	for _, v := range values {
		if s := string(v); s != "" && s != "0" {
			return s
		}
	}
	return ""
}

// parseSidecarDate tries a few common formats gallery-dl emits. The first
// returned non-empty value wins.
func parseSidecarDate(values ...string) *time.Time {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, v); err == nil {
				return &parsed
			}
		}
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
