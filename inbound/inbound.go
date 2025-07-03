package inbound

type Inbound interface {
	Start() error
	Close() error
}
