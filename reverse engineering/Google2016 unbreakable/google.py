import angr

def char(state, n):
	vec = state.se.BVS('c{}'.format(n), 8, explicit_name=True)
	return vec, state.se.And(vec >= ord(' '), vec <= ord('~'))

project = angr.Project("./unbreakable-enterprise-product-activation")
state = project.factory.blank_state(addr = 0x4005bd)
for i in range(51):
	c, cond = char(state, i)
	state.memory.store(0x6042c0 + i, c)
	state.add_constraints(cond)
	
path = project.factory.path(state)
exp = project.surveyors.Explorer(start=path, find=(0x400830,), avoid=(0x400850,))
exp.run()
flag = exp._f.state.se.any_str(exp._f.state.memory.load(0x6042c0, 51))
print flag