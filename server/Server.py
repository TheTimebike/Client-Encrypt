import rsa, socket, sys, threading, re, bcrypt, time, json, hashlib, sys, os

def generate_new_password(password):
    new_password = bcrypt.hashpw(str(password).encode("utf-8"),'$2b$12$RNX81nG9fLReXWMVEdmp8e'.encode("utf-8"))
    return new_password
  
max_connections = 10 # Amount of clients to connect to

is_compiled = False
root_file_path = "./" if not is_compiled else sys._MEIPass

class Logging:

    def log(message):
        if True:
            print(message)
            with open("server_logs.txt", "a+") as out:
                out.write(str(message) + "\n")

Logging.log(generate_new_password("test"))

disabled_md5_list = []
if not os.path.isfile(root_file_path + "Client.exe"):
    Logging.log("Debug: Cannot find client comparison file and checksum for windows machines will be disabled.")
    disabled_md5_list.append("EXE")
if not os.path.isfile(root_file_path + "Client.app"):
    Logging.log("Debug: Cannot find client comparison file and checksum for apple machines will be disabled.")
    disabled_md5_list.append("APP")
Logging.log(disabled_md5_list)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_address = sys.argv[1]
socket_port = int(sys.argv[2])
try:
    s.bind((socket_address,socket_port))
except socket.error as e:
    Logging.log(e)

Logging.log(s.getsockname()[0])
s.listen(max_connections)

Logging.log("Waiting for connections")

class Security():
    
    def fetch_md5(filePath):
        hash_md5 = hashlib.md5()
        with open(filePath, "rb") as out:
            for chunk in iter(lambda: out.read(), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

connection_list = {}
class Messaging():
    
    def send_to_all(message, sender):
        for attr, value in connection_list.items():
            value[0].sendall(rsa.encrypt("[{0}]: {1}".format(sender, message.decode()).encode(), value[1]))

    def server_announce(message, recipient, key):
        recipient.sendall(rsa.encrypt(message.encode(), key))

    def server_announce_to_all(message, internal):
        for attr, value in connection_list.items():
            value[0].sendall(rsa.encrypt("{2}[{0}]: {1}".format("Server", message, internal).encode(), value[1]))

    def user_request_pingback():
        name_list = ""
        for attr, value in connection_list.items():
            name_list += "{0}: {1}, ".format(value[2], value[3])
        return "<INTERNAL:-USER_REQUEST_PINGBACK:>" + nameList[:-1]

        # Alternate list compression method

        #nameList = ""
        #    [nameList += "{0}: {1}, ".format(value[2], value[3]) for attr, value in connectionList.items()]
        #        return "<INTERNAL:-USER_REQUEST_PINGBACK:>" + nameList[:-1]

def threaded_client(connection, address):
    try:
        connection_name = "{0}:{1}".format(address[0], address[1])
        string_public_key = connection.recv(1024).decode() # Recieve and format the client's public key
        if not string_public_key.startswith("-----BEGIN RSA PUBLIC KEY-----") or not string_public_key.endswith("-----END RSA PUBLIC KEY-----\n"):
            connection.close()
            return
        else:
            try:
                connection_public = rsa.PublicKey.load_pkcs1(string_public_key.encode(), format="PEM")
            except:
                return
            (server_public, server_private) = rsa.newkeys(1024)
            connection.sendall("{0}".format(rsa.PublicKey.save_pkcs1(server_public, format="PEM").decode()).encode())
            
            # MD5 Checksum, different based on OS ensure OS based check // Possible to be disabled due to issues
            
            client_md5 = rsa.decrypt(connection.recv(1024), server_private).decode()

            def check_client(client_md5):
                if client_md5.startswith("<INTERNAL:-CHECKSUMAPP:>"):
                    if "APP" in disabled_list:
                        return None
                    if client_md5.replace("<INTERNAL:-CHECKSUMAPP:>", "") == Security.fetch_md5("./Client.app"):
                        Logging.log("Verified MacOS")
                        return True

                elif client_md5.startswith("<INTERNAL:-CHECKSUMEXE:>"):
                    if "EXE" in disabled_list:
                        return None
                    if client_md5.replace("<INTERNAL:-CHECKSUMEXE:>", "") == Security.fetch_md5("./Client.exe"):
                        Logging.log("Verified Windows")
                        return True
                return False

            #checkedReturn = checkClient(clientMd5)
            #if not checkedReturn:
            #    return
            #elif checkedReturn == None:
            #    print("Unable to compare")

            connection.sendall(rsa.encrypt("Please Enter the Password:".encode(), connection_public))
            
            decrypted_password = rsa.decrypt(connection.recv(1024), server_private)
            # Pull the comparative value from a JSON file.
            if decrypted_password.decode() != generate_new_password("test"):
                connection.close()
               	Logging.log("Connection to {0} Denied Due To Incorrect Password.".format(connection_name))
                return 
            
            Logging.log("Connection to {0} Verified.".format(connection_name))
            return_data = rsa.encrypt("RSA Verified. Securely Connected to the server.".encode(), connection_public)    
            connection.sendall(returnData)
            Messaging.server_announce_to_all("{0} Has Joined.".format(connection_name), "<INTERNAL:-USER_JOIN:>")

        ip = "{0}:{1}".format(address[0], address[1])
        connection_list[connection_name] = [connection, connection_public, connection_name, ip]

        while True:
            data = rsa.decrypt(connection.recv(1024), server_private)
            Logging.log(data.decode())
            if data.decode() == "<INTERNAL:-DISCONNECT:>":
                Logging.log("Disconnected from {0}".format(connection_name))
                break

            elif data.decode() == "<INTERNAL:-REQUEST_USERS:>":
                Messaging.server_announce(Messaging.user_request_pingback(), connection, connection_public)

            elif data.decode().startswith("<INTERNAL:-REQUEST_NAME_CHANGE:>"):
                new_connection_name, connection_data = data.decode()[32:], connection_list[name]; connection_data[2] = new_connection_name
                del connectionList[name]
                connectionList[newName] = connectionData; name = newName
                Logging.log(connection_ist)
            else:
                Messaging.send_to_all(data, connection_name)

        #connection.sendall(rsa.encrypt("[{0}]: {1}".format(name, data.decode()).encode(), formattedPublic))
        connection.close()
        del connection_list[name]
        Messaging.server_announce_to_all("{0} Has Left.".format(connection_name), "<INTERNAL:-USER_LEAVE:>")
        return

    except ConnectionResetError:
        if connection_list.get(connection_name, None) != None:
            Logging.log("Disonnected from {0}".format("Unknown"))
            del connection_list[name]
            Messaging.server_announce_to_all("{0} Has Left.".format(connection_name), "<INTERNAL:-USER_LEAVE:>")
        return      
  
    except Exception as ex:
        if connection_list.get(connection_name, None) != None:
            Logging.log(ex)
            del connection_list[name]
            return
    
while True:
    connection, address = s.accept()
    Logging.log("Connected to {0}:{1}".format(address[0], address[1]))
    thread = threading.Thread(target=threaded_client,args=(connection,address))
    thread.daemon = True
    thread.start()
