package rules

import (
	"fmt"
	"strings"
	"time"
)

// TimeWindow defines an allowed time window
type TimeWindow struct {
	Days  []time.Weekday
	Start time.Duration // offset from midnight
	End   time.Duration // offset from midnight
}

// TimeRule matches requests based on current time
type TimeRule struct {
	windows  []TimeWindow
	location *time.Location
}

// NewTimeRule creates a new time-based rule
func NewTimeRule(windows []TimeWindow, location *time.Location) *TimeRule {
	if location == nil {
		location = time.UTC
	}
	return &TimeRule{
		windows:  windows,
		location: location,
	}
}

// ParseTimeWindow parses a time window from config format
func ParseTimeWindow(days []string, start, end string) (TimeWindow, error) {
	tw := TimeWindow{}

	// Parse days
	dayMap := map[string]time.Weekday{
		"sun": time.Sunday, "sunday": time.Sunday,
		"mon": time.Monday, "monday": time.Monday,
		"tue": time.Tuesday, "tuesday": time.Tuesday,
		"wed": time.Wednesday, "wednesday": time.Wednesday,
		"thu": time.Thursday, "thursday": time.Thursday,
		"fri": time.Friday, "friday": time.Friday,
		"sat": time.Saturday, "saturday": time.Saturday,
	}

	for _, d := range days {
		day, ok := dayMap[strings.ToLower(d)]
		if !ok {
			return tw, fmt.Errorf("invalid day: %s", d)
		}
		tw.Days = append(tw.Days, day)
	}

	// Parse start time (HH:MM format)
	startTime, err := parseTimeOfDay(start)
	if err != nil {
		return tw, fmt.Errorf("invalid start time: %w", err)
	}
	tw.Start = startTime

	// Parse end time
	endTime, err := parseTimeOfDay(end)
	if err != nil {
		return tw, fmt.Errorf("invalid end time: %w", err)
	}
	tw.End = endTime

	return tw, nil
}

func parseTimeOfDay(s string) (time.Duration, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}

// Evaluate checks if the current time falls within any configured window
func (r *TimeRule) Evaluate(ctx *Context) Result {
	now := time.Now().In(r.location)
	currentDay := now.Weekday()
	currentTime := time.Duration(now.Hour())*time.Hour + time.Duration(now.Minute())*time.Minute

	for _, w := range r.windows {
		// Check if current day is in the window
		dayMatch := false
		for _, d := range w.Days {
			if d == currentDay {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			continue
		}

		// Check if current time is in the window
		if currentTime >= w.Start && currentTime <= w.End {
			return Result{
				Matched: true,
				Reason:  fmt.Sprintf("time %s matches window", now.Format("Mon 15:04")),
				Labels:  []string{"time-allowed"},
			}
		}
	}

	return Result{
		Matched: false,
		Reason:  fmt.Sprintf("time %s outside allowed windows", now.Format("Mon 15:04")),
	}
}

// Type returns the rule type
func (r *TimeRule) Type() string {
	return "time_window"
}
