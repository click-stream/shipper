package common

type Processors struct {
	list []*Processor
}

func (ps *Processors) Add(p *Processor) {

	ps.list = append(ps.list, p)
}

func (ps *Processors) Items() []*Processor {

	return ps.list
}

func NewProcessors() *Processors {
	return &Processors{}
}
