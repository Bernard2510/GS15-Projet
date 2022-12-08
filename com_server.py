import os

def push_to_server(username,name,content):
    
    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)

    #if server doesnt exist
    try:
        os.mkdir(server_path)
    except OSError:
        pass

    #if user folder doesnt exist
    try:
        os.mkdir(user_path)
    except OSError:
        pass
    
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    with open(file_path,mode='w') as file:
        file.write(content)


def fetch_from_server(username,name):

    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        return lines[0]

def remove_from_server(username,name):

    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    filename = name+".txt"
    file_path=os.path.join(user_path,filename)
    os.remove(file_path)

def remove_user(username):

    server_path=os.getcwd()+"\server"
    user_path=os.path.join(server_path,username)
    os.rmdir(user_path)


push_to_server("test","cle","123")
print(fetch_from_server("test","cle"))
remove_from_server("test","cle")
remove_user("test")

