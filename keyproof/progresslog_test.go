package keyproof

import "sync/atomic"

type TestFollower struct {
	count int64
}

func (_ *TestFollower) StepStart(desc string, intermediates int) {}

func (t *TestFollower) Tick() {
	atomic.AddInt64(&t.count, 1)
}

func (t *TestFollower) StepDone() {}

func init() {
	Follower = &TestFollower{}
}
