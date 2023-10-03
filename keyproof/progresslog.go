package keyproof

type (
	ProgressFollower interface {
		StepStart(desc string, intermediates int)
		Tick()
		StepDone()
	}

	EmptyFollower struct{}
)

func (*EmptyFollower) StepStart(_ string, _ int) {}
func (*EmptyFollower) Tick()                     {}
func (*EmptyFollower) StepDone()                 {}

var Follower ProgressFollower = &EmptyFollower{}
