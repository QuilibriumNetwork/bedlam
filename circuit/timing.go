//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"time"
)

// Timing records timing samples and renders a profiling report.
type Timing struct {
	Start   time.Time
	Samples []*Sample
}

// NewTiming creates a new Timing instance.
func NewTiming() *Timing {
	return &Timing{
		Start: time.Now(),
	}
}

// Sample adds a timing sample with label and data columns.
func (t *Timing) Sample(label string, cols []string) *Sample {
	start := t.Start
	if len(t.Samples) > 0 {
		start = t.Samples[len(t.Samples)-1].End
	}
	sample := &Sample{
		Label: label,
		Start: start,
		End:   time.Now(),
		Cols:  cols,
	}
	t.Samples = append(t.Samples, sample)
	return sample
}

// Sample contains information about one timing sample.
type Sample struct {
	Label   string
	Start   time.Time
	End     time.Time
	Abs     time.Duration
	Cols    []string
	Samples []*Sample
}

// SubSample adds a sub-sample for a timing sample.
func (s *Sample) SubSample(label string, end time.Time) {
	start := s.Start
	if len(s.Samples) > 0 {
		start = s.Samples[len(s.Samples)-1].End
	}
	s.Samples = append(s.Samples, &Sample{
		Label: label,
		Start: start,
		End:   end,
	})
}

// AbsSubSample adds an absolute sub-sample for a timing sample.
func (s *Sample) AbsSubSample(label string, duration time.Duration) {
	s.Samples = append(s.Samples, &Sample{
		Label: label,
		Abs:   duration,
	})
}
