package drda

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
)

type A struct {
	B string
	C []byte
	D byte
}

type decoder struct {
	br *bytes.Reader
}

func (d *decoder) value(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Ptr:
		if err := d.value(v.Elem()); err != nil {
			return err
		}
	case reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err := d.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		l := v.NumField()
		for i := 0; i < l; i++ {
			if v := v.Field(i); v.CanSet() || t.Field(i).Name != "_" {
				if err := d.value(v); err != nil {
					return err
				}
			}
		}

	// case reflect.Slice:
	// 	l := v.Len()
	// 	for i := 0; i < l; i++ {
	// 		d.value(v.Index(i))
	// 	}

	case reflect.String, reflect.Slice:
		l1, err := d.br.ReadByte()
		if err != nil {
			return err
		}
		l2, err := d.br.ReadByte()
		if err != nil {
			return err
		}
		length := int(l2) | int(l1)<<8
		b := make([]byte, length)
		n, err := d.br.Read(b)
		if n != length || err != nil {
			return errors.New("prase string error")
		}
		v.SetString(string(b))

	case reflect.Bool:
		b, err := d.br.ReadByte()
		if err != nil {
			return errors.New("prase uint8 error")
		}
		if b == 0x00 {
			v.SetBool(false)
		} else {
			v.SetBool(true)
		}

	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		s := int(v.Type().Size())
		b := make([]byte, s)
		n, err := d.br.Read(b)
		if n != s || err != nil {
			return errors.New("prase uint error")
		}
		i, _ := binary.Uvarint(b)
		v.SetUint(i)
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		s := int(v.Type().Size())
		b := make([]byte, s)
		n, err := d.br.Read(b)
		if n != s || err != nil {
			return errors.New("prase int error")
		}
		i, _ := binary.Varint(b)
		v.SetInt(i)

	}
	return nil
}

func decode(br *bytes.Reader, obj any) error {
	rv := reflect.ValueOf(obj).Elem()
	for i := 0; i < rv.NumField(); i++ {
		fv := rv.Field(i)
		switch fv.Kind() {
		case reflect.Uint8:
			b, err := br.ReadByte()
			if err != nil {
				return errors.New("prase uint8 error")
			}
			fv.SetUint(uint64(b))
		case reflect.Int8:
			b, err := br.ReadByte()
			if err != nil {
				return errors.New("prase int8 error")
			}
			fv.SetInt(int64(b))
		case reflect.Uint16:
			b := make([]byte, 2)
			n, err := br.Read(b)
			if n != 2 || err != nil {
				return errors.New("prase uint16 error")
			}
			fv.SetUint(uint64(binary.BigEndian.Uint16(b)))
		case reflect.Int16:
			b := make([]byte, 2)
			n, err := br.Read(b)
			if n != 2 || err != nil {
				return errors.New("prase int16 error")
			}
			fv.SetInt(int64(binary.BigEndian.Uint16(b)))
		case reflect.Uint32:
			b := make([]byte, 4)
			n, err := br.Read(b)
			if n != 4 || err != nil {
				return errors.New("prase uint32 error")
			}
			fv.SetUint(uint64(binary.BigEndian.Uint32(b)))
		case reflect.Int32:
			b := make([]byte, 4)
			n, err := br.Read(b)
			if n != 4 || err != nil {
				return errors.New("prase int32 error")
			}
			fv.SetInt(int64(binary.BigEndian.Uint32(b)))
		case reflect.Uint64:
			b := make([]byte, 8)
			n, err := br.Read(b)
			if n != 8 || err != nil {
				return errors.New("prase uint64 error")
			}
			fv.SetUint(uint64(binary.BigEndian.Uint64(b)))
		case reflect.Int64:
			b := make([]byte, 8)
			n, err := br.Read(b)
			if n != 8 || err != nil {
				return errors.New("prase int64 error")
			}
			fv.SetInt(int64(binary.BigEndian.Uint64(b)))
		case reflect.String:
			l1, err := br.ReadByte()
			if err != nil {
				return err
			}
			l2, err := br.ReadByte()
			if err != nil {
				return err
			}
			length := int(l2) | int(l1)<<8
			b := make([]byte, length)
			n, err := br.Read(b)
			if n != length || err != nil {
				return errors.New("prase string error")
			}
			fv.SetString(string(b))
		case reflect.Slice:
			if fv.Type().Elem().Kind() == reflect.Uint8 {
				l1, err := br.ReadByte()
				if err != nil {
					return err
				}
				l2, err := br.ReadByte()
				if err != nil {
					return err
				}
				length := int(l2) | int(l1)<<8
				b := make([]byte, length)
				n, err := br.Read(b)
				if n != length || err != nil {
					return errors.New("prase string error")
				}
				fv.SetBytes(b)
			}
		}
	}
	return nil
}
