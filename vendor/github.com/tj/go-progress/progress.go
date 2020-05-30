// Package progress provides a simple terminal progress bar.
package progress

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"
)

// Bar is a progress bar.
type Bar struct {
	StartDelimiter string  // StartDelimiter for the bar ("|").
	EndDelimiter   string  // EndDelimiter for the bar ("|").
	Filled         string  // Filled section representation ("█").
	Empty          string  // Empty section representation ("░")
	Total          float64 // Total value.
	Width          int     // Width of the bar.

	value float64
	tmpl  *template.Template
	text  string
}

// New returns a new bar with the given total.
func New(total float64) *Bar {
	b := &Bar{
		StartDelimiter: "|",
		EndDelimiter:   "|",
		Filled:         "█",
		Empty:          "░",
		Total:          total,
		Width:          60,
	}

	b.Template(`{{.Percent | printf "%3.0f"}}% {{.Bar}} {{.Text}}`)

	return b
}

// NewInt returns a new bar with the given total.
func NewInt(total int) *Bar {
	return New(float64(total))
}

// Text sets the text value.
func (b *Bar) Text(s string) {
	b.text = s
}

// Value sets the value.
func (b *Bar) Value(n float64) {
	if n > b.Total {
		panic("Bar update value cannot be greater than the total")
	}
	b.value = n
}

// ValueInt sets the value.
func (b *Bar) ValueInt(n int) {
	b.Value(float64(n))
}

// Percent returns the percentage
func (b *Bar) percent() float64 {
	return (b.value / b.Total) * 100
}

// Bar returns the progress bar string.
func (b *Bar) bar() string {
	p := b.value / b.Total
	filled := math.Ceil(float64(b.Width) * p)
	empty := math.Floor(float64(b.Width) - filled)
	s := b.StartDelimiter
	s += strings.Repeat(b.Filled, int(filled))
	s += strings.Repeat(b.Empty, int(empty))
	s += b.EndDelimiter
	return s
}

// String returns the progress bar.
func (b *Bar) String() string {
	var buf bytes.Buffer

	data := struct {
		Value          float64
		Total          float64
		Percent        float64
		StartDelimiter string
		EndDelimiter   string
		Bar            string
		Text           string
	}{
		Value:          b.value,
		Text:           b.text,
		StartDelimiter: b.StartDelimiter,
		EndDelimiter:   b.EndDelimiter,
		Percent:        b.percent(),
		Bar:            b.bar(),
	}

	if err := b.tmpl.Execute(&buf, data); err != nil {
		panic(err)
	}

	return buf.String()
}

// WriteTo writes the progress bar to w.
func (b *Bar) WriteTo(w io.Writer) (int64, error) {
	s := fmt.Sprintf("\r   %s ", b.String())
	_, err := io.WriteString(w, s)
	return int64(len(s)), err
}

// Template for rendering. This method will panic if the template fails to parse.
func (b *Bar) Template(s string) {
	t, err := template.New("").Parse(s)
	if err != nil {
		panic(err)
	}

	b.tmpl = t
}
