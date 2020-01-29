package common

import "sync"

type Inputs struct {
	list []*Input
}

func (is *Inputs) Add(i *Input) {

	is.list = append(is.list, i)
}

func (is *Inputs) Start(wg *sync.WaitGroup) {

	for _, i := range is.list {

		if i != nil {
			(*i).Start(wg)
		}
	}
}

func NewInputs() *Inputs {
	return &Inputs{}
}
