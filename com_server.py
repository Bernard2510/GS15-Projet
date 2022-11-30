import os

def push_to_server(username,name,content):
    
    server_path=os.getcwd()+"\server"

    #if server doesnt exist
    try:
        os.mkdir(server_path)
    except OSError:
        pass

    filename = username+"_"+name+".txt"
    file_path=os.path.join(server_path,filename)
    with open(file_path,mode='w') as file:
        file.write(content)


def pull_from_server(username,name):

    server_path=os.getcwd()+"\server"
    filename = username+"_"+name+".txt"
    file_path=os.path.join(server_path,filename)
    with open(file_path, mode='r') as file:
        lines = file.readlines()
        return lines[0]

def remove_from_server(username,name):

    server_path=os.getcwd()+"\server"
    filename = username+"_"+name+".txt"
    file_path=os.path.join(server_path,filename)
    os.remove(file_path)


push_to_server("test","cle","123")
print(pull_from_server("test","cle"))
remove_from_server("test","cle")

