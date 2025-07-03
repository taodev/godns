package inbound

import (
	"context"
	"errors"
	"os"
	"sync"
)

type Manager struct {
	access       sync.Mutex
	registry     *Registry
	started      bool
	inbounds     []Inbound
	inboundByTag map[string]Inbound
}

func NewManager() *Manager {
	return &Manager{
		registry:     NewRegistry(),
		inboundByTag: make(map[string]Inbound),
	}
}

func (m *Manager) Start() error {
	m.access.Lock()
	if m.started {
		panic("already started")
	}
	m.started = true
	inbounds := m.inbounds
	m.access.Unlock()
	for _, inbound := range inbounds {
		if err := inbound.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Close() error {
	m.access.Lock()
	if !m.started {
		return nil
	}
	inbounds := m.inbounds
	m.access.Unlock()
	var errs []error
	for _, inbound := range inbounds {
		if err := inbound.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) Inbounds() []Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return m.inbounds
}

func (m *Manager) Get(tag string) (Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return nil, false
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.inboundByTag, tag)
	index := -1
	for i, it := range m.inbounds {
		if it == inbound {
			index = i
			break
		}
	}
	if index == -1 {
		panic("invalid inbound index")
	}
	m.inbounds = append(m.inbounds[:index], m.inbounds[index+1:]...)
	started := m.started
	m.access.Unlock()
	if started {
		return inbound.Close()
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, tag string, inboundType string, options any) error {
	inbound, err := m.registry.Create(ctx, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if existsInbound, loaded := m.inboundByTag[tag]; loaded {
		if m.started {
			if err = existsInbound.Close(); err != nil {
				return err
			}
		}
		existsIndex := -1
		for i, it := range m.inbounds {
			if it == inbound {
				existsIndex = i
				break
			}
		}
		if existsIndex == -1 {
			panic("invalid inbound index")
		}
		m.inbounds = append(m.inbounds[:existsIndex], m.inbounds[existsIndex+1:]...)
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	return nil
}
