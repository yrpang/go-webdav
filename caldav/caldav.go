// Package caldav provides a client and server CalDAV implementation.
//
// CalDAV is defined in RFC 4791.
package caldav

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/internal"
)

var CapabilityCalendar = webdav.Capability("calendar-access")

func NewCalendarHomeSet(path string) webdav.BackendSuppliedHomeSet {
	return &calendarHomeSet{Href: internal.Href{Path: path}}
}

// ValidateCalendarObject checks the validity of a calendar object according to
// the contraints layed out in RFC 4791 section 4.1 and returns the only event
// type and UID occuring in this calendar, or an error if the calendar could
// not be validated.
func ValidateCalendarObject(cal *ical.Calendar) (eventType string, uid string, err error) {
	// Calendar object resources contained in calendar collections
	// MUST NOT specify the iCalendar METHOD property.
	if prop := cal.Props.Get(ical.PropMethod); prop != nil {
		return "", "", fmt.Errorf("calendar resource must not specify METHOD property")
	}

	for _, comp := range cal.Children {
		// Calendar object resources contained in calendar collections
		// MUST NOT contain more than one type of calendar component
		// (e.g., VEVENT, VTODO, VJOURNAL, VFREEBUSY, etc.) with the
		// exception of VTIMEZONE components, which MUST be specified
		// for each unique TZID parameter value specified in the
		// iCalendar object.
		if comp.Name != ical.CompTimezone {
			if eventType == "" {
				eventType = comp.Name
			}
			if eventType != comp.Name {
				return "", "", fmt.Errorf("conflicting event types in calendar: %s, %s", eventType, comp.Name)
			}
			// TODO check VTIMEZONE for each TZID?
		}

		// Calendar components in a calendar collection that have
		// different UID property values MUST be stored in separate
		// calendar object resources.
		compUID, err := comp.Props.Text(ical.PropUID)
		if err != nil {
			return "", "", fmt.Errorf("error checking component UID: %v", err)
		}
		if uid == "" {
			uid = compUID
		}
		if compUID != "" && uid != compUID {
			return "", "", fmt.Errorf("conflicting UID values in calendar: %s, %s", uid, compUID)
		}
	}
	return eventType, uid, nil
}

type Calendar struct {
	Path                  string
	Name                  string
	Description           string
	MaxResourceSize       int64
	SupportedComponentSet []string
	SupportedCalendarData []CalendarDataType
	Color                 string
	ColorSymbolic         string
	Order                 *int
}

type CalendarColor struct {
	Value    string
	Symbolic string
}

type CalendarCompRequest struct {
	Name string

	AllProps bool
	Props    []string

	AllComps bool
	Comps    []CalendarCompRequest

	Expand *CalendarExpandRequest
}

type CalendarExpandRequest struct {
	Start, End time.Time
}

type CompFilter struct {
	Name         string
	IsNotDefined bool
	Start, End   time.Time
	Props        []PropFilter
	Comps        []CompFilter
}

type ParamFilter struct {
	Name         string
	IsNotDefined bool
	TextMatch    *TextMatch
}

type PropFilter struct {
	Name         string
	IsNotDefined bool
	Start, End   time.Time
	TextMatch    *TextMatch
	ParamFilter  []ParamFilter
}

type TextMatch struct {
	Text            string
	NegateCondition bool
}

type CalendarQuery struct {
	CompRequest CalendarCompRequest
	CompFilter  CompFilter
}

type CalendarMultiGet struct {
	Paths       []string
	CompRequest CalendarCompRequest
}

type CalendarObject struct {
	Path          string
	ModTime       time.Time
	ContentLength int64
	ETag          string
	Data          *ical.Calendar
}

type CalendarDataType struct {
	ContentType string
	Version     string
}

type CalendarSyncQuery struct {
	SyncToken   string
	Limit       int
	DataRequest *CalendarCompRequest
}

type CalendarSyncResponse struct {
	SyncToken string
	Updated   []CalendarObject
	Deleted   []string
}

var (
	validSyncTokenName              = xml.Name{Space: internal.Namespace, Local: "valid-sync-token"}
	syncLevelName                   = xml.Name{Space: internal.Namespace, Local: "sync-level"}
	numberOfMatchesWithinLimitsName = xml.Name{Space: internal.Namespace, Local: "number-of-matches-within-limits"}
)

type syncLevelError struct {
	XMLName xml.Name `xml:"DAV: sync-level"`
	Level   string   `xml:",chardata"`
}

// NewValidSyncTokenError returns the DAV:valid-sync-token precondition failure.
func NewValidSyncTokenError() error {
	return &internal.HTTPError{
		Code: http.StatusForbidden,
		Err: &internal.Error{
			Raw: []internal.RawXMLValue{
				*internal.NewRawXMLElement(validSyncTokenName, nil, nil),
			},
		},
	}
}

// NewSyncLevelError returns the DAV:sync-level precondition failure indicating
// that the requested sync-level is not supported.
func NewSyncLevelError(levels ...string) error {
	level := ""
	if len(levels) > 0 {
		level = strings.Join(levels, " ")
	}

	raw, err := internal.EncodeRawXMLElement(&syncLevelError{Level: level})
	if err != nil {
		return internal.HTTPErrorf(http.StatusForbidden, "caldav: unsupported sync-level")
	}

	return &internal.HTTPError{
		Code: http.StatusForbidden,
		Err: &internal.Error{
			Raw: []internal.RawXMLValue{*raw},
		},
	}
}

// NewNumberOfMatchesWithinLimitsError returns the DAV:number-of-matches-within-limits error.
func NewNumberOfMatchesWithinLimitsError() error {
	return &internal.HTTPError{
		Code: http.StatusInsufficientStorage,
		Err: &internal.Error{
			Raw: []internal.RawXMLValue{
				*internal.NewRawXMLElement(numberOfMatchesWithinLimitsName, nil, nil),
			},
		},
	}
}
