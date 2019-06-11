package keyproof

type TestFollower struct {
	count int
}

func (_ *TestFollower) StepStart(desc string, intermediates int) {}

func (t *TestFollower) Tick() {
	t.count++
}

func (t *TestFollower) StepDone() {}

func init() {
	Follower = &TestFollower{}
}
