import socket, sys, threading, re, time, bcrypt os, json, hashlib
from tkinter import *

class Logging:

    def log(message):
        if True:
            print(message)

class SocketHandler:

    def start(_server, _port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server = _server
        port = _port
        s.connect((server,port))
        return s

class Security:

    def verify_connection(socket, client_public, client_private):
        system_string = ""#Security.set_system_type()
        if system_string == False:
            return system_string
        client_public_string = rsa.PublicKey.save_pkcs1(client_public, format="PEM").decode().encode()
        socket.send(client_public_string)
        data = socket.recv(2048).decode()
        if not data.startswith("-----BEGIN RSA PUBLIC KEY-----") or not data.endswith("-----END RSA PUBLIC KEY-----\n"):
            return False
        try:
            app.set_server_public(rsa.PublicKey.load_pkcs1(data.encode(), format="PEM"))
        except:
            return False
        md5_checksum_hash = rsa.encrypt(str(system_string + Security.fetch_md5()).encode(), app.server_public)
        socket.send(md5_checksum_hash)
        Logging.log("Waiting for pingback of md5 checksum")
        password_request = rsa.decrypt(socket.recv(2048), client_private).decode()
        Logging.log("Md5 checksum received")
        app.message_display_box.insert("end", password_request)
        app.connected = True
        decode_messages(socket, client_private, app)

    def fetch_md5():
        hash_md5 = hashlib.md5()
        with open(sys.executable, "rb") as out:
            for data_chunk in iter(lambda: out.read(), b""):
                hash_md5.update(data_chunk)
        return hash_md5.hexdigest()

    def set_system_type():
        if str(sys.executeable).endswith(".exe"):
            return "<INTERNAL:-CHECKSUMEXE:>"
        elif str(sys.executable).endswith(".app"):
            return "<INTERNAL:-CHECKSUMAPP:>"
        return False

class Config():
    def __init__(self):
        self.filepath = "./config.json"
        with open(self.filepath, "r") as out:
            self.config_data = json.load(out)
        self.join_msg = BooleanVar()
        self.join_msg.set(self.config_data["join_msg"])
        self.leave_msg = BooleanVar()
        self.leave_msg.set(self.config_data["leave_msg"])

    def toggle_join_msg(self):
        self.config_data["join_msg"] = (self.config_data["join_msg"] == False)
        self.save_config

    def toggle_leave_msg(self):
        self.config_data["leave_msg"] = (self.config_data["leave_msg"] == False)
        self.save_config

    def save_config(self):
        with open(filepath, "w") as out:
            json.dump(self.config_data, out, indent=4)

class SubWindow():
    def __init__(self, main_window, name):
        self.master = Toplevel(main_window)
        self.master.geometry("400x200")
        self.master.resizable(False, False)
        self.master.wm_title(name)

        self.text_box = Listbox(self.master, width=64, height=11)
        #self.scrollbar = Scrollbar(self.text_box)
        self.text_box.place(x=5,y=5)

    def add_text(self, message):
        self.text_box.insert("end", message)

class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.configuration = Config()
        self.verified, self.connected = False, False
        self.master = master
        self._init_objects()

    def _init_objects(self):
        self.master.title("ClientEncrypt")
        self.master.bind("<Escape>", self.file_btn_quit_command)
        self.master.bind("<F5>", self.security_btn_reload_command)

        self.message_display_box = Listbox(self.master, width=64, height=18)
        self.message_display_box.place(x=5,y=5)

        self.message_input_box = Text(self.master, width=48, height=5)
        self.message_input_box.place(x=5,y=300)
        self.message_input_box.bind("<Return>", self.send_message)

        self.disconnect_button = Button(self.master, width=25, height=5, text="Connect", command=self.file_btn_connect_command)
        self.disconnect_button.place(x=5,y=390)

        self.send_button = Button(self.master, width=25, height=5, text="Send", command=self.send_message)
        self.send_button.place(x=208,y=390)

        self.menu_bar = Menu(self.master)
        self.master.config(menu=self.menu_bar)
        file, security, options, social = Menu(self.menu_bar), Menu(self.menu_bar), Menu(self.menu_bar), Menu(self.menu_bar)

        file.add_command(label="Connnect", command=self.file_btn_connect_command)
        file.add_command(label="Disconnect", command=self.file_btn_disconnect_command)
        file.add_command(label="Quit", command=self.file_btn_quit_command)

        security.add_command(label="Reload RSA Keys", command=self.security_btn_reload_command)

        options.add_command(label="Clear Messages", command=self.options_btn_clear_command)
        options.add_command(label="Change Name", command=self.options_btn_name_command)

        social.add_command(label="List Connected Users", command=self.social_btn_list_command_request)
        social.add_checkbutton(label="Toggle Join Messages", onvalue=True, offvalue=False, variable=self.configuration.join_msg, command=self.social_btn_join_command)
        social.add_checkbutton(label="Toggle Leave Messages", onvalue=True, offvalue=False, variable=self.configuration.join_msg, command=self.social_btn_leave_command)

        self.menu_bar.add_cascade(label="Client", menu=file)
        self.menu_bar.add_cascade(label="Security", menu=security)
        self.menu_bar.add_cascade(label="Options", menu=options)
        self.menu_bar.add_cascade(label="Settings", menu=social)

    def set_server_public(self, server_public):
        self.server_public = server_public

    def send_message(self, en=None):
        inputted_message = self.message_input_box.get('1.0', END)
        inputted_message = inputted_message if not inputted_message.endswith("\n") else inputted_message[:-1]
        Logging.log("|{0}|".format(inputted_message))
        self.message_input_box.delete("1.0", END)
        Logging.log("|{0}|".format(self.message_input_box.get('1.0', END)))
        if not self.verified:
            Logging.log("Sending a hashed message")
            encrypted_password = bcrypt.hashpw(str(inputted_message).encode("utf-8"),'$2b$12$RNX81nG9fLReXWMVEdmp8e'.encode("utf-8"))
            Logging.log(encrypted_password)
            self.socket.send(rsa.encrypt(encrypted_password, self.server_public))
            self.verified = True
        else:
            Logging.log("Sending an unhashed message")
            self.socket.send(rsa.encrypt(str(inputted_message).encode(), self.server_public))
        Logging.log("Connection status: {0}".format(self.connected))
        Logging.log("Verification status: {0}".format(self.verified))
        return "break"

    def file_btn_connect_command(self, en=None):
        if not self.connected:
            (self.client_public, self.client_private) = rsa.newkeys(1024)
            self.socket = SocketHandler.start("localhost", 12345)
            self.main_thread = threading.Thread(target=Security.verify_connection, args=(self.socket, self.client_public, self.client_private)) 
            self.main_thread.daemon = True
            self.main_thread.start()
            self.disconnect_button.config(text="Disconnect", command=self.file_btn_disconnect_command)
            self.connected = True

    def file_btn_disconnect_command(self, en=None):
        encrypted_message = rsa.encrypt("<INTERNAL:-DISCONNECT:>".encode(), self.server_public)
        self.socket.send(encrypted_message)
        if self.connected or self.verified:
            del self.main_thread
        Logging.log("Disconnected from clientside")
        self.connected, self.verified = False, False
        self.disconnect_button.config(text="Connect", command=self.file_btn_connect_command)
    
    def file_btn_quit_command(self, en=None):
        quit()

    def security_btn_reload_command(self, en=None):
        if self.connected:
            self.file_btn_disconnect_command()
        self.file_btn_disconnect_command()
    
    def options_btn_clear_command(self):
        self.message_display_box.delete("1.0", END)

    def options_btn_name_command(self):
        self.socket.send(rsa.encrypt("<INTERNAL:-REQUEST_NAME_CHANGE:>Bob".encode(), self.server_public))

    def social_btn_list_command(self, online_members):
        self.member_box = SubWindow(self.master, "Online Members")
        for member in online_members:
            self.member_box.add_text(member)

    def social_btn_list_command_request(self):
        self.socket.send(rsa.encrypt("<INTERNAL:-REQUEST_USERS:>".encode(), self.server_public))

    def social_btn_join_command(self):
        self.configuration.toggle_join_msg()

    def social_btn_leave_command(self):
        self.configuration.toggle_leave_msg()

def decode_messages(socket, client_private, app):
    while True:
        Logging.log("Threading takeover")
        data = socket.recv(2048)
        if data == b"":
            app.verified = False
            app.connected = False
            app.disconnect_button.config(text="Connect", command=app.file_btn_connect_command)
            return
        new_data = rsa.decrypt(data, client_private).decode()
        Logging.log("Data Recieved: {0}".format(new_data))
        if bool(re.search("<INTERNAL:-(.*):>", new_data)):
            if new_data.startswith("<INTERNAL:-USER_JOIN:>") and app.join_messages:
                app.message_display_box.insert("end", new_data.replace("<INTERNAL:-USER_JOIN:>", ""))
            elif new_data.startswith("<INTERNAL:-USER_LEAVE:>") and app.leave_messages:
                app.message_display_box.insert("end", new_data.replace("<INTERNAL:-USER_LEAVE:>", ""))
            elif new_data.startswith("<INTERNAL:-USER_REQUEST_PINGBACK:>"):
                Logging.log(new_data[34:])
                user_list = list( new_data[34:].split(",") ) # Server will return data in JSON format
                # Note: Make sure the server wont forward any internal commands so that users cannot force other clients to take actions
                app.social_btn_list_command(user_list)
        else:
            app.message_display_box.insert("end", new_data)

root = Tk()
root.geometry("400x480")
root.resizable(False, False)
app = Window(root)
root.mainloop()
