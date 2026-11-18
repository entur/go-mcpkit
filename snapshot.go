package mcpkit

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
)

// snapshot returns a copy of v that shares no memory with it, so a
// descriptor, schema or capability the caller keeps cannot change what an
// endpoint serves or validates.
//
// Typed parts are copied value by value, so property order and bytes are
// unchanged; shared and cyclic pointers stay shared and cyclic in the copy. A
// value held in an empty interface (metadata, enum and const values, schema
// extras) is replaced by the plain JSON tree of its encoding at this moment,
// with json.Number for numbers: later mutation, private state or pointer
// identity behind it can no longer change what is served. Anything that
// cannot be snapshotted that way is an error, never a panic or a stack
// overflow: an interface-held value JSON cannot encode (a cycle, found where
// it occurs; NaN; a channel), an unexported field, a func, a non-empty
// interface or a map key that is not a scalar.
func snapshot[T any](v T) (T, error) {
	c := copier{seen: map[ptrKey]reflect.Value{}}
	out := c.copy(reflect.ValueOf(&v).Elem())
	if c.err != nil {
		var zero T
		return zero, fmt.Errorf("snapshot %T: %w", v, c.err)
	}
	return out.Interface().(T), nil
}

type ptrKey struct {
	p uintptr
	t reflect.Type
	n int // slice length: a shorter slice of the same array is not a cycle
}

type copier struct {
	seen map[ptrKey]reflect.Value
	err  error
}

func (c *copier) fail(format string, args ...any) reflect.Value {
	if c.err == nil {
		c.err = fmt.Errorf(format, args...)
	}
	return reflect.Value{}
}

func (c *copier) copy(v reflect.Value) reflect.Value {
	if c.err != nil {
		return reflect.Zero(v.Type())
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		key := ptrKey{p: v.Pointer(), t: v.Type()}
		if p, ok := c.seen[key]; ok {
			return p
		}
		p := reflect.New(v.Type().Elem())
		c.seen[key] = p
		c.set(p.Elem(), c.copy(v.Elem()))
		return p
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		if v.Type().NumMethod() != 0 {
			return c.fail("non-empty interface %s", v.Type())
		}
		if err := acyclic(v.Elem(), map[ptrKey]bool{}); err != nil {
			return c.fail("%w", err)
		}
		raw, err := json.Marshal(v.Elem().Interface())
		if err != nil {
			return c.fail("%w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var tree any
		if err := dec.Decode(&tree); err != nil {
			return c.fail("%w", err)
		}
		out := reflect.New(v.Type()).Elem()
		if tree != nil {
			out.Set(reflect.ValueOf(tree))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			c.set(out.Index(i), c.copy(v.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := range v.Len() {
			c.set(out.Index(i), c.copy(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		if k := v.Type().Key().Kind(); k < reflect.Bool || k > reflect.Float64 && k != reflect.String {
			return c.fail("map key %s is not a scalar", v.Type().Key())
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for it := v.MapRange(); it.Next(); {
			if value := c.copy(it.Value()); c.err == nil {
				out.SetMapIndex(it.Key(), value)
			}
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				return c.fail("%s has unexported fields", v.Type())
			}
			c.set(out.Field(i), c.copy(v.Field(i)))
		}
		return out
	case reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Complex64, reflect.Complex128:
		return c.fail("unsupported %s", v.Type())
	}
	return v
}

// acyclic reports a cycle of pointers, maps or slices in a value JSON would
// walk, at the depth where it closes: encoding/json notices one only after a
// thousand levels, which can exhaust a small stack first. A marshaler's
// encoding is its own and is not walked.
func acyclic(v reflect.Value, path map[ptrKey]bool) error {
	if v.Type().Implements(reflect.TypeFor[json.Marshaler]()) || v.Type().Implements(reflect.TypeFor[encoding.TextMarshaler]()) {
		return nil
	}
	switch v.Kind() {
	case reflect.Interface:
		if !v.IsNil() {
			return acyclic(v.Elem(), path)
		}
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if v.IsNil() {
			return nil
		}
		key := ptrKey{p: uintptr(v.UnsafePointer()), t: v.Type()}
		if v.Kind() == reflect.Slice {
			key.n = v.Len()
		}
		if path[key] {
			return fmt.Errorf("cyclic %s", v.Type())
		}
		path[key] = true
		defer delete(path, key)
		if v.Kind() == reflect.Pointer {
			return acyclic(v.Elem(), path)
		}
		if v.Kind() == reflect.Map {
			for it := v.MapRange(); it.Next(); {
				if err := acyclic(it.Value(), path); err != nil {
					return err
				}
			}
			return nil
		}
		fallthrough
	case reflect.Array:
		for i := range v.Len() {
			if err := acyclic(v.Index(i), path); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				if err := acyclic(v.Field(i), path); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// set stores value in dst unless copying already failed.
func (c *copier) set(dst, value reflect.Value) {
	if c.err == nil {
		dst.Set(value)
	}
}
