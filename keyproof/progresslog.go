package keyproof

type (
	ProgressFollower interface {
		StepStart(desc string, intermediates int)
		Tick()
		StepDone()
	}

	EmptyFollower struct{}
)

func (_ *EmptyFollower) StepStart(_ string, _ int) {}
func (_ *EmptyFollower) Tick()                     {}
func (_ *EmptyFollower) StepDone()                 {}

var Follower ProgressFollower = &EmptyFollower{}
