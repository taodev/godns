package inbound

import (
	"context"
	"errors"
	"sync"
)

type ConstructorFunc[T any] func(ctx context.Context, tag string, options *T) (Inbound, error)

func Register[Options any](registry *Registry, inboundType string, constructor ConstructorFunc[Options]) {
	registry.register(inboundType, func() any {
		return new(Options)
	}, func(ctx context.Context, tag string, rawOptions any) (Inbound, error) {
		var options *Options
		if rawOptions != nil {
			options = rawOptions.(*Options)
		}
		return constructor(ctx, tag, options)
	})
}

type (
	optionsConstructorFunc func() any
	constructorFunc        func(ctx context.Context, tag string, options any) (Inbound, error)
)

type Registry struct {
	access      sync.Mutex
	optionsType map[string]optionsConstructorFunc
	constructor map[string]constructorFunc
}

func NewRegistry() *Registry {
	return &Registry{
		optionsType: make(map[string]optionsConstructorFunc),
		constructor: make(map[string]constructorFunc),
	}
}

func (r *Registry) CreateOptions(inboundType string) (any, bool) {
	r.access.Lock()
	defer r.access.Unlock()
	optionsConstructor, loaded := r.optionsType[inboundType]
	if !loaded {
		return nil, false
	}
	return optionsConstructor(), true
}

func (r *Registry) Create(ctx context.Context, inboundType string, tag string, options any) (Inbound, error) {
	r.access.Lock()
	defer r.access.Unlock()
	constructor, loaded := r.constructor[inboundType]
	if !loaded {
		return nil, errors.New("inbound type not found: " + inboundType)
	}
	return constructor(ctx, tag, options)
}

func (r *Registry) register(inbountType string, optionsConstructor optionsConstructorFunc, constructor constructorFunc) {
	r.access.Lock()
	defer r.access.Unlock()
	r.optionsType[inbountType] = optionsConstructor
	r.constructor[inbountType] = constructor
}
