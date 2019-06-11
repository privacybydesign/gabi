package keyproof

type ProgressFollower interface {
	StepStart(desc string, intermediates int)
	Tick()
	StepDone()
}

type EmptyFollower struct{}

func (_ *EmptyFollower) StepStart(desc string, intermediates int) {}
func (_ *EmptyFollower) Tick()                                    {}
func (_ *EmptyFollower) StepDone()                                {}

var Follower ProgressFollower = &EmptyFollower{}
