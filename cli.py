from permissions_package.permissions import AccessControl, Role, ActionType, User

acl = AccessControl()
admin_role = Role('admin')
normal_role = Role('normal_user')

acl.add_role(admin_role.get_name())
acl.add_role(normal_role.get_name())
acl.add_resource('resource1')
acl.add_resource('resource2')

acl.add_rule(ActionType.READ, normal_role.get_name(), 'resource1')
acl.add_rule(ActionType.READ, normal_role.get_name(), 'resource2')

acl.add_rule(ActionType.READ, admin_role.get_name(), 'resource1')
acl.add_rule(ActionType.READ, admin_role.get_name(), 'resource2')
acl.add_rule(ActionType.DELETE, admin_role.get_name(), 'resource1')
acl.add_rule(ActionType.DELETE, admin_role.get_name(), 'resource2')
acl.add_rule(ActionType.WRITE, admin_role.get_name(), 'resource1')
acl.add_rule(ActionType.WRITE, admin_role.get_name(), 'resource2')

def cli_print(user_name):
    if user_name == 'admin':
        return f"\nhi! you are logged in as {user_name}\n"\
           "press 1 for login as another user\n"\
           "press 2 for create user\n"\
           "press 3 for edit role\n"

    return f"\nhi! you are logged in as {user_name}\n"\
           "press 1 for login as another user\n"\
           "press 2 for view roles\n"\
           "press 3 for access resource\n"


def login_user(users, current_user):
    print('enter user name')
    user_name = input()
    if user_name in users.keys():
        return users.get(user_name)
    else:
        print("user does not exist")
        return current_user


def create_user(users):
    print('enter user name')
    user_name = input()
    if user_name in users.keys():
        print("user already exist")
    else:
        users[user_name] = User(user_name, roles=[normal_role])
        print("user created")


def show_roles(current_user):
    print("user has below roles:")
    for role in current_user.get_roles():
        print(role.name)


def edit_role(current_user):
    print("user has below roles:")
    for role in current_user.get_roles():
        print(role.name)

    print("enter role you want to change:")
    role_name = input()
    for role in current_user.get_roles():
        if role.get_name() == role_name:
            print("role changed\n")
            return

    print("role does not belong to this user")


def resources(current_user):
    print("below are the resources available")
    for resource in acl.get_resources():
        print(f"{resource}\n")

    print('enter resource you want to work on')
    resource = input()
    for i in range(5):
        if i == 4:
            print("max limit exceed")
            return
        if resource not in acl.get_resources():
            print('resource not available')
            resource = input()
        else:
            break

    for role in current_user.get_roles():
        for action_type in ActionType:
            if acl.is_action_allowed(action_type, role.get_name(), resource):
                print(f"User has '{action_type.value}' access on '{resource}' with role '{role.get_name()}'")


def main():
    users = {}
    current_user = User(admin_role.get_name(), roles=[admin_role])
    users['admin'] = current_user

    while True:
        print(cli_print(current_user.name))
        option = int(input())
        if option == 1:
            current_user = login_user(users, current_user)
            print(f"logged in user : {current_user.name}")

        elif option == 2:
            if current_user.name == 'admin':
                create_user(users)
            else:
                show_roles(current_user)

        elif option == 3:
            if current_user.name == 'admin':
                edit_role(current_user)
            else:
                resources(current_user)

        else:
            print("enter correct input")


if __name__ == '__main__':
    main()