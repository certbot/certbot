_cache = {}


def save_entry(module_name, name, cache):
    try:
        module_cache = _cache[module_name]
    except KeyError:
        module_cache = _cache[module_name] = {}
    module_cache[name] = cache


def _create_get_from_cache(number):
    def _get_from_cache(module_name, name, get_cache_values):
        try:
            return _cache[module_name][name][number]
        except KeyError:
            v = get_cache_values()
            save_entry(module_name, name, v)
            return v[number]
    return _get_from_cache


get_type = _create_get_from_cache(0)
get_docstring_signature = _create_get_from_cache(1)
get_docstring = _create_get_from_cache(2)
