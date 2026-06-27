def new_items(old_list, new_list, key):

    old = {item[key] for item in old_list if key in item}

    return [
        item
        for item in new_list
        if item.get(key) not in old
    ]
