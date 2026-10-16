//go:build !darwin

package netwatch

// quietSource never reports a change. twarpd runs on macOS; elsewhere only
// the periodic tick of Watch applies.
type quietSource struct{ events chan struct{} }

// Open returns a source without events on systems other than macOS.
func Open() (Source, error) {
	return &quietSource{events: make(chan struct{})}, nil
}

func (source *quietSource) Events() <-chan struct{} { return source.events }

func (source *quietSource) Close() error { return nil }
