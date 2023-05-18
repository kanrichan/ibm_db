package main

import (
	"os"
	"reflect"
	"strings"
	"text/template"

	"github.com/kanrichan/ibm_db/drda"
)

// GenDadaType GenDadaType
type GenDadaType struct {
	Name    string
	Columns []GenDadaColumn
}

// GenDadaColumn GenDadaColumn
type GenDadaColumn struct {
	Name   string
	Type   string
	Len    string
	Flag   bool
	Endian string
	Encode string
	Digit  int
}

func main() {
	tmpl, err := template.ParseFiles("generator/decode.tmpl")
	if err != nil {
		panic(err)
	}
	set := GenSet{Types: make([]GenDadaType, 0)}
	set.Append(reflect.TypeOf(&drda.SQLDARD{}).Elem())
	fi, err := os.OpenFile("drda/decode.go", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer fi.Close()
	err = tmpl.Execute(fi, set)
	if err != nil {
		panic(err)
	}
}

type GenSet struct {
	Types []GenDadaType
}

func (set *GenSet) Append(rt reflect.Type) {
	for i := range set.Types {
		if set.Types[i].Name == rt.Name() {
			return
		}
	}
	var cols = make([]GenDadaColumn, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		cols[i].Name = rt.Field(i).Name
		switch {
		case rt.Field(i).Type.Kind() == reflect.Array && rt.Field(i).Type.Elem().Kind() == reflect.Uint8:
			cols[i].Type = "[*]byte"
		case rt.Field(i).Type.Kind() == reflect.Slice && rt.Field(i).Type.Elem().Kind() == reflect.Uint8:
			cols[i].Type = "[]byte"
		case rt.Field(i).Type.Kind() == reflect.Slice && rt.Field(i).Type.Elem().Kind() == reflect.Ptr &&
			rt.Field(i).Type.Elem().Elem().Kind() == reflect.Struct:
			cols[i].Type = "[]*struct"
			cols[i].Len = rt.Field(i).Tag.Get("len")
			set.Append(rt.Field(i).Type.Elem().Elem())
		case rt.Field(i).Type.Kind() == reflect.Ptr && rt.Field(i).Type.Elem().Kind() == reflect.Struct:
			cols[i].Type = rt.Field(i).Name
			set.Append(rt.Field(i).Type.Elem())
			if i != 0 && strings.HasSuffix(cols[i-1].Name, "FLAG") {
				cols[i].Flag = true
			}
		default:
			cols[i].Type = rt.Field(i).Type.Kind().String()
		}
	}
	set.Types = append(set.Types, GenDadaType{
		Name:    rt.Name(),
		Columns: cols,
	})
}
