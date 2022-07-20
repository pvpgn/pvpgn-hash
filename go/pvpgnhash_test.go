package pvpgnhash

import (
	"strconv"
	"testing"
	"time"
)

func TestGetHash(t *testing.T) {
	start := time.Now()
	hash := GetHash("12345")
	elapsed := time.Since(start)
	if hash != "460e0af6c1828a93fe887cbe103d6ca6ab97a0e4" {
		t.Errorf("Exprect hash result. %v", hash)
	}

	t.Logf("execute time= %s\n", elapsed.String())
}

func BenchmarkGetHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetHash(strconv.Itoa(i))
	}
}
