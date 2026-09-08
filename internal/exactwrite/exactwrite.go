package exactwrite

import (
	"errors"
	"io"
)

func Bytes(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) {
			return errors.New("writer returned an invalid count")
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
