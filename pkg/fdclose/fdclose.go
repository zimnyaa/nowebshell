package fdclose

//#include "fdclose.h"
import "C"

func Fdclose(pid int, fd int) int {
	return int(C.fdclose(C.int(pid), C.int(fd)))
}
