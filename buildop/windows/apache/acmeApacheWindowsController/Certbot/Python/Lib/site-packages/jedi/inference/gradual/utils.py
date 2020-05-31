import os

from jedi.inference.gradual.typeshed import TYPESHED_PATH, create_stub_module


def load_proper_stub_module(inference_state, file_io, import_names, module_node):
    """
    This function is given a random .pyi file and should return the proper
    module.
    """
    path = file_io.path
    assert path.endswith('.pyi')
    if path.startswith(TYPESHED_PATH):
        # /foo/stdlib/3/os/__init__.pyi -> stdlib/3/os/__init__
        rest = path[len(TYPESHED_PATH) + 1: -4]
        split_paths = tuple(rest.split(os.path.sep))
        # Remove the stdlib/3 or third_party/3.5 part
        import_names = split_paths[2:]
        if import_names[-1] == '__init__':
            import_names = import_names[:-1]

    if import_names is not None:
        actual_value_set = inference_state.import_module(import_names, prefer_stubs=False)

        stub = create_stub_module(
            inference_state, actual_value_set, module_node, file_io, import_names
        )
        inference_state.stub_module_cache[import_names] = stub
        return stub
    return None
