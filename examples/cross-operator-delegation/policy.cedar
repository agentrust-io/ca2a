// Child operator's LOCAL policy (domain B).
//
// The effective permission on an inbound peer call is the DELEGATED leaf scope
// intersected with what this policy permits. The child was delegated
// {task:read, task:write}; this policy permits {task:read, task:audit}. So the
// effective scope is {task:read}: task:write is delegated but not locally
// permitted, and task:audit is locally permitted but never delegated.
//
// Each capability is evaluated as a Cedar authorization request whose action id
// is the capability name (see ca2a_runtime.cedar.CedarPolicy).
permit(
  principal,
  action in [Action::"task:read", Action::"task:audit"],
  resource
);
