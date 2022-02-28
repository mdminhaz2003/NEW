"""
===========================================================================================================
                                File        main.py ( Full project code here included )
                                Author      MD. MINHAZ
                                Email       mdm047767@gmail.com
                                Hire Me     https://pph.me/mdminhaz2003/
                                Repo Link   https://github.com/mdminhaz2003/PDF-Layout-Reader/ (Private Repo)
                                Location    Dhaka, Bangladesh
                                Date        18-02-2022 at 4:56 PM
===========================================================================================================
"""
import os
import json
import re
import pdftotext
import ntplib
import ftplib
from datetime import datetime
import calendar
import time
import requests
from uttlv import TLV
from pathlib import Path
import base64
import qrcode
from reportlab.pdfgen import canvas
from PyPDF2 import PdfFileWriter
from PyPDF2 import PdfFileReader
from tkinter import *
from tkinter.ttk import *
from typing import Union, Optional, Dict, Tuple, Any
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from tkinter import messagebox
from tkinter import filedialog


# Basic Widget Class
class Widget:
    def __init__(self, master, frame_text: str):
        self.frame = LabelFrame(master=master, text=frame_text, padding=10)
        self.frame.grid(row=0, column=0, padx=10, pady=10)

    # Button Widget
    def button(self, text: str, command, row: int, col: int, width: int = 30) -> Union[Button, Button]:
        btn = Button(master=self.frame, text=text, padding=5, width=width, command=command)
        btn.grid(row=row, column=col, padx=5, pady=5)
        return btn

    # Entry Widget
    def edit_text(self, label_text: str, row: int, width: int = 65, show=None) -> Entry:
        Label(master=self.frame, text=label_text).grid(row=row, column=0, padx=5, pady=5)
        edit_text_value = Entry(master=self.frame, width=width, show=show)
        edit_text_value.grid(row=row, column=1, padx=5, pady=5, columnspan=2)
        return edit_text_value

    # Checkbutton Widget
    def check_button(
            self,
            check_button_text: str,
            variable_name: IntVar,
            command, row: int,
            col: int
    ) -> Union[Checkbutton, Checkbutton]:
        check_btn = Checkbutton(master=self.frame, text=check_button_text, variable=variable_name, command=command)
        check_btn.grid(row=row, column=col, padx=20, pady=20, columnspan=1)
        return check_btn

    # Label widget
    def label(self, label_text: str, row: int, col: int) -> Union[Label, Label]:
        label = Label(master=self.frame, text=label_text)
        label.grid(row=row, column=col, padx=5, pady=5)
        return label


# Error Message Dialog Box Function
def err_message_dialog(field_name: str, empty: bool = True) -> None:
    if empty:
        messagebox.showwarning("Empty Field", f"{field_name} can't be empty !")
    elif not empty:
        messagebox.showwarning("Invalid Input", f"{field_name} should be whole number.")
    else:
        messagebox.showwarning("Wrong !", "Something went wrong !")


# Get Edit text field value Function
def field_value(field_name: Entry) -> str:
    return field_name.get()


# Delete Edit Text field value Function
def delete_field_value(field_name: Entry) -> None:
    return field_name.delete(0, "end")


# Check Empty Edit Text field Function
def is_empty(field_name: Entry) -> bool:
    return False if len(field_value(field_name=field_name)) > 0 else True


# Get Checkbutton status code using this Function.
def check_btn_status(btn_variable: IntVar) -> int:
    return btn_variable.get()


# Set Edit Text Config (disabled or enabled)
def set_config(field_name: Entry, config: str) -> Optional[Dict[str, Tuple[str, str, str, Any, Any]]]:
    return field_name.config(state=config)


def check_button_function(btn_variable: IntVar, *fields: Entry) -> None:
    btn_status = check_btn_status(btn_variable=btn_variable)
    if btn_status == 0:
        for x in fields:
            delete_field_value(field_name=x)
            set_config(field_name=x, config="disabled")
    else:
        for x in fields:
            delete_field_value(field_name=x)
            set_config(field_name=x, config="enabled")


# File select Edit text function.
def file_select(field_name: Entry, *field: str) -> None:
    delete_field_value(field_name=field_name)
    file_path = filedialog.askopenfilename(
        title=field[0],
        filetypes=[(field[1], field[2])]
    )
    if field[3] == "False":
        field_name.insert(0, os.path.dirname(file_path))
    else:
        field_name.insert(0, file_path)


# Language Choice Screen UI part her designed
def language_choice() -> None:
    widget = Widget(master=root, frame_text="Select a Language :")
    widget.button(
        text="Arabic",
        command=lambda: functional_screen(
            frame_text='حدد اختيارا :',
            create_statement_text='إنشاء البيانات',
            create_setting_file_text='إنشاء ملف الإعداد',
            close_window_text='أغلق النافذة',
            language='Arabic'
        ),
        row=0,
        col=0
    )
    widget.button(
        text="English",
        command=lambda: functional_screen(
            frame_text='Select an option :',
            create_statement_text='Create Statements',
            create_setting_file_text='Create Setting File',
            close_window_text='Close Window',
            language='English'
        ),
        row=1,
        col=0
    )
    widget.button(
        text="Quit",
        command=root.quit,
        row=2,
        col=0
    )


# Functional Screen Function
def functional_screen(
        frame_text: str,
        create_statement_text: str,
        create_setting_file_text: str,
        close_window_text: str,
        language: str
) -> None:
    def functional_screen_ui(enter_admin_password_text: str, submit_text: str) -> None:
        functional_screen_window = Toplevel(master=root)
        functional_screen_window.resizable(False, False)
        widget = Widget(master=functional_screen_window, frame_text=frame_text)
        widget.button(
            text=create_statement_text,
            command=create_statement,
            row=0,
            col=0
        )
        widget.button(
            text=create_setting_file_text,
            command=lambda: admin_login_screen(
                enter_admin_password_text=enter_admin_password_text,
                submit_text=submit_text,
                close_window_text=close_window_text,
                language=language
            ),
            row=1,
            col=0
        )
        widget.button(text=close_window_text, command=functional_screen_window.destroy, row=2, col=0)

    if language == "Arabic":
        functional_screen_ui(enter_admin_password_text='أدخل كلمة مرور المسؤول :', submit_text='إرسال')
        log_file("Arabic language has been selected for processing", False)
    else:
        log_file("English language has been selected for processing", False)
        functional_screen_ui(enter_admin_password_text="Enter Admin Password", submit_text="Submit")


# Admin Login screen for Create setting file
def admin_login_screen(
        enter_admin_password_text: str,
        submit_text: str,
        close_window_text: str,
        language: str
) -> None:
    admin_login_screen_window = Toplevel(root)
    admin_login_screen_window.resizable(False, False)

    widget = Widget(master=admin_login_screen_window, frame_text=enter_admin_password_text)
    user_password = widget.edit_text(label_text=enter_admin_password_text, width=30, row=0, show="*")
    text = widget.label(label_text="", row=1, col=1)

    def checking_password(passwd: Entry):
        if is_empty(passwd):
            text.config(text="Password can\'t be empty")
            log_file("Attempted to proceed with blank password", False)
            delete_field_value(passwd)
        elif len(field_value(passwd)) < 8:
            text.config(text="Length of Password should be at least 8")
            log_file("Attempted to proceed with password less than 8 characters", False)
            delete_field_value(passwd)
        elif len(field_value(passwd)) == 8 and field_value(passwd) != "12345678":
            text.config(text="Wrong Password ! Try Again !")
            log_file("Attempted to proceed with incorrect password", False)
            delete_field_value(passwd)
        elif len(field_value(passwd)) == 8 and field_value(passwd) == "12345678":
            log_file("Password authentication completed successfully", False)
            text.config(text="Successfully logged in.")
            delete_field_value(passwd)
            admin_login_screen_window.destroy()

            if language == 'Arabic':
                create_setting_file(
                    input_valid_information_text='إدخال معلومات صحيحة',
                    submit_text=submit_text,
                    close_window_text=close_window_text
                )
            else:
                create_setting_file(
                    input_valid_information_text="Input Valid Information",
                    submit_text=submit_text,
                    close_window_text=close_window_text
                )
        else:
            text.config(text="Something went wrong ! Try Again")
            log_file("Tried to enter an invalid password or something else.", False)
            delete_field_value(passwd)

    widget.button(text=submit_text, command=lambda: checking_password(user_password), row=2, col=0, width=15)
    widget.button(text=close_window_text, command=admin_login_screen_window.destroy, row=2, col=2, width=15)


# Create setting file function here covered
def create_setting_file(
        input_valid_information_text: str,
        submit_text: str,
        close_window_text: str
) -> None:
    setting_screen_window = Toplevel(master=root)
    setting_screen_window.resizable(False, False)
    widget = Widget(master=setting_screen_window, frame_text=input_valid_information_text)
    username = widget.edit_text(label_text="Username", row=0)
    company_name = widget.edit_text(label_text="Company Name", row=1)
    vat_identifier = widget.edit_text(label_text="VAT Identifier", row=2)
    vat_identifier.insert(0, "15%|15.0%|VAT|Value|Added|Tax|TAX|vat")
    total_identifier = widget.edit_text(label_text="Total Identifier", row=3)
    total_identifier.insert(0, "Total|TOTAL|G.Total|G. Total|total")
    qr_location_x = widget.edit_text(label_text="QR Location X (cm)", row=4)
    qr_location_y = widget.edit_text(label_text="QR Location Y (cm)", row=5)
    qr_size = widget.edit_text(label_text="QR Code Size (cm)", row=6)
    qr_size.insert(0, "3")
    local_drive_folder_location = widget.edit_text(label_text="Local Drive Folder Location", row=7)
    local_drive_folder_location.insert(0, "Select a file")
    local_drive_folder_location.bind(
        "<Button-1>", lambda a="Select any file", b="Any File", c="*.*", d="False": file_select(
            local_drive_folder_location, a, b, c, d
        )
    )
    google_drive_check_btn_status = IntVar()
    widget.check_button(
        check_button_text="Google Drive Folder", variable_name=google_drive_check_btn_status,
        command=lambda: check_button_function(
            google_drive_check_btn_status,
            google_drive_access_token,
            google_drive_folder_id
        ), row=8, col=0
    )
    one_drive_folder_check_btn_status = IntVar()
    widget.check_button(
        check_button_text="OneDrive Folder", variable_name=one_drive_folder_check_btn_status,
        command=lambda: check_button_function(
            one_drive_folder_check_btn_status,
            one_drive_folder
        ), row=8, col=1
    )
    ftp_server_check_btn_status = IntVar()
    widget.check_button(
        check_button_text="FTP Server", variable_name=ftp_server_check_btn_status,
        command=lambda: check_button_function(
            ftp_server_check_btn_status,
            ftp_ip,
            ftp_username,
            ftp_password,
            ftp_folder_location
        ), row=8, col=2
    )
    google_drive_access_token = widget.edit_text(label_text="Access Token", row=9)
    google_drive_folder_id = widget.edit_text(label_text="Google Drive Folder ID", row=10)
    one_drive_folder = widget.edit_text(label_text="OneDrive Folder", row=11)
    ftp_ip = widget.edit_text(label_text="FTP IP", row=12)
    ftp_username = widget.edit_text(label_text="FTP Username", row=13)
    ftp_password = widget.edit_text(label_text="FTP Password", row=14, show="*")
    ftp_folder_location = widget.edit_text(label_text="FTP Folder Location", row=15)
    all_fields = [username, company_name, vat_identifier, total_identifier, qr_location_x, qr_location_y, qr_size,
                  local_drive_folder_location, google_drive_access_token, google_drive_folder_id, one_drive_folder,
                  ftp_ip, ftp_username, ftp_password, ftp_folder_location]
    # disable all additional fields without local drive field
    for field in all_fields[8:]:
        set_config(field_name=field, config="disabled")

    def checking_input_validity() -> None:
        if is_empty(username):
            log_file("Attempted to create setting file with empty username", False)
            err_message_dialog("Username")
        elif is_empty(company_name):
            log_file("Attempted to create setting file with empty company name", False)
            err_message_dialog('Company Name')
        elif is_empty(vat_identifier):
            log_file("Attempted to create setting file with empty VAT identifier", False)
            err_message_dialog("VAT Identifier")
        elif is_empty(total_identifier):
            log_file("Attempted to create setting file with empty Total identifier", False)
            err_message_dialog("Total Identifier")
        elif is_empty(qr_location_x):
            log_file("Attempted to create setting file with empty QR code location X", False)
            err_message_dialog("QR Code Location X (cm)")
        elif is_empty(qr_location_y):
            log_file("Attempted to create setting file with empty QR code location Y", False)
            err_message_dialog("QR Code Location Y (cm)")
        elif is_empty(qr_size):
            log_file("Attempted to create setting file with empty QR code size", False)
            err_message_dialog("QR code box size (cm)")
        elif is_empty(local_drive_folder_location) or field_value(local_drive_folder_location) == 'Select a file':
            log_file("Attempted to create setting file with empty Local Drive Folder Location", False)
            err_message_dialog("Local Drive Folder Location")
        elif check_btn_status(google_drive_check_btn_status) == 1 and is_empty(google_drive_access_token):
            log_file("Attempted to create setting file with empty Google Drive Access Token", False)
            err_message_dialog("Google Drive Access Token")
        elif check_btn_status(google_drive_check_btn_status) == 1 and is_empty(google_drive_folder_id):
            log_file("Attempted to create setting file with empty Google Drive Folder ID", False)
            err_message_dialog("Google Drive Folder ID")
        elif check_btn_status(one_drive_folder_check_btn_status) == 1 and is_empty(one_drive_folder):
            log_file("Attempted to create setting file with empty OneDrive Folder", False)
            err_message_dialog("OneDrive Folder")
        elif check_btn_status(ftp_server_check_btn_status) == 1 and is_empty(ftp_ip):
            log_file("Attempted to create setting file with empty FTP IP", False)
            err_message_dialog("FTP IP")
        elif check_btn_status(ftp_server_check_btn_status) == 1 and is_empty(ftp_username):
            log_file("Attempted to create setting file with empty FTP Username", False)
            err_message_dialog("FTP Username")
        elif check_btn_status(ftp_server_check_btn_status) == 1 and is_empty(ftp_password):
            log_file("Attempted to create setting file with empty FTP Password", False)
            err_message_dialog("FTP Password")
        elif check_btn_status(ftp_server_check_btn_status) == 1 and is_empty(ftp_folder_location):
            log_file("Attempted to create setting file with empty FTP Folder Location", False)
            err_message_dialog("FTP Folder Location")
        elif field_value(username) != "root2020":
            log_file("Attempted to create setting file with incorrect username", False)
            err_message_dialog("Username")
        elif not field_value(qr_location_x).isdigit():
            log_file("Attempted to create setting file with invalid QR code location X (cm).", False)
            err_message_dialog("QR Code Location X (cm)", False)
        elif not field_value(qr_location_y).isdigit():
            log_file("Attempted to create setting file with invalid QR code location Y (cm).", False)
            err_message_dialog("QR Code Location Y (cm)", False)
        elif not field_value(qr_size).isdigit():
            log_file("Attempted to create setting file with invalid QR code size (cm).", False)
            err_message_dialog("QR Code Size (cm)", False)
        else:
            user_input = {
                "username": field_value(username),
                "setting_file_name": "setting.env",
                "vat_identifier": field_value(vat_identifier),
                "total_identifier": field_value(total_identifier),
                "company_name": field_value(company_name),
                "qr_location_x": field_value(qr_location_x),
                "qr_location_y": field_value(qr_location_y),
                "qr_size": field_value(qr_size),
                "local_drive_folder_location": field_value(local_drive_folder_location),
                "google_drive_access_token": field_value(google_drive_access_token),
                "google_drive_folder_id": field_value(google_drive_folder_id),
                "one_drive_folder": field_value(one_drive_folder),
                "ftp_ip": field_value(ftp_ip),
                "ftp_username": field_value(ftp_username),
                "ftp_password": field_value(ftp_password),
                "ftp_folder_location": field_value(ftp_folder_location)
            }

            # Deleting all value from current screen
            for delete_field in all_fields:
                delete_field_value(delete_field)

            write_setting_file_func(values=user_input)
            setting_screen_window.destroy()

    widget.button(
        text=submit_text,
        command=lambda: checking_input_validity(),
        row=16,
        col=0,
        width=16
    )
    widget.button(
        text="Log File",
        command=log_file_user_input,
        row=16,
        col=1,
        width=16
    )
    widget.button(text=close_window_text, command=setting_screen_window.destroy, row=16, col=2, width=16)


# Write setting file
def write_setting_file_func(
        values: dict
) -> None:
    # creating key
    key = Fernet.generate_key()
    cipher_code = Fernet(key)

    def encryption_func(key_name: str) -> str:
        return cipher_code.encrypt(values[key_name].encode('utf-8')).decode('utf-8')

    # Getting all values from user input
    key = key.decode('utf-8')
    username = encryption_func(key_name="username")
    setting_file_name = encryption_func(key_name="setting_file_name")
    company_name = encryption_func(key_name="company_name")
    vat_identifier = encryption_func(key_name="vat_identifier")
    total_identifier = encryption_func(key_name="total_identifier")
    qr_location_x = encryption_func(key_name="qr_location_x")
    qr_location_y = encryption_func(key_name="qr_location_y")
    qr_size = encryption_func(key_name="qr_size")
    local_drive_folder_location = encryption_func(key_name="local_drive_folder_location")
    google_drive_access_token = encryption_func(key_name="google_drive_access_token")
    google_drive_folder_id = encryption_func(key_name="google_drive_folder_id")
    one_drive_folder = encryption_func(key_name="one_drive_folder")
    ftp_ip = encryption_func(key_name="ftp_ip")
    ftp_username = encryption_func(key_name="ftp_username")
    ftp_password = encryption_func(key_name="ftp_password")
    ftp_folder_location = encryption_func(key_name="ftp_folder_location")

    # Creating File template here
    template = f"ADMIN_USERNAME={username}\nFILE_NAME={setting_file_name}\nVAT_IDENTIFIER={vat_identifier}\n" \
               f"TOTAL_IDENTIFIER={total_identifier}\nCOMPANY_NAME={company_name}\nRANDOM={key}\n" \
               f"QR_LOC_X={qr_location_x}\nQR_LOC_Y={qr_location_y}\nQR_SIZE={qr_size}\n" \
               f"LOCAL_FILE_LOC={local_drive_folder_location}\nGOOGLE_DRIVE_TOKEN={google_drive_access_token}\n" \
               f"GOOGLE_DRIVE_FOLDER_ID={google_drive_folder_id}\nONE_DRIVE_FOLDER={one_drive_folder}\n" \
               f"FTP_IP={ftp_ip}\nFTP_USERNAME={ftp_username}\nFTP_PASSWORD={ftp_password}\n" \
               f"FTP_FOLDER_LOC={ftp_folder_location}\n"

    # Creating setting file path
    path = os.path.join(values["local_drive_folder_location"], "setting.env")

    # write setting file now
    with open(path, 'w') as write:
        write.write(template)
        write.close()

    log_file(
        log_message=f"Successfully Created a new Setting file. File Location : {values['local_drive_folder_location']}",
        setting_file_path=f"{values['local_drive_folder_location']}"
    )
    messagebox.showinfo("Successful !", f"Successfully created setting.env file inside :\n"
                                        f"{local_drive_folder_location}")
    upload_google_drive(file_path=path, setting_file_path=f"{values['local_drive_folder_location']}")
    upload_one_drive(file_path=path, setting_file_path=f"{values['local_drive_folder_location']}")
    upload_ftp_server(file_path=path, setting_file_path=f"{values['local_drive_folder_location']}")


# Creating Log file
def log_file(
        log_message: str,
        setting_file: bool = True,
        setting_file_path: str = None,
) -> None:
    data = None
    cipher_code = None
    date_time = datetime.now()
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_info.json")

    def date_time_encryption_text_func(key_name: str) -> str:
        return cipher_code.encrypt(date_time.strftime(key_name).encode('utf-8')).decode('utf-8')

    if setting_file:
        if setting_file_path is not None:
            setting_file_data = read_setting_file_func(path=setting_file_path)
            key = setting_file_data["key"].encode('utf-8')
            cipher_code = Fernet(key)

            def dict_value_encryption_text_func(key_name: str) -> str:
                return cipher_code.encrypt(setting_file_data[key_name].encode('utf-8')).decode('utf-8')

            data = {
                "random": key.decode("utf-8"),
                "username": dict_value_encryption_text_func("username"),
                "task": cipher_code.encrypt(log_message.encode('utf-8')).decode('utf-8'),
                "company_name": dict_value_encryption_text_func("company_name"),
                "local_drive_folder_loc": dict_value_encryption_text_func("local_drive_folder_location"),
                "date": date_time_encryption_text_func(key_name="%d %B, %Y"),
                "weekday": date_time_encryption_text_func(key_name="%A"),
                "time": date_time_encryption_text_func(key_name="%I:%M:%S %p")
            }
        else:
            print("Enter yor setting file path for create a log item.")
    else:
        # creating key
        key = Fernet.generate_key()
        cipher_code = Fernet(key)

        def encryption_func(key_name: str) -> str:
            return cipher_code.encrypt(key_name.encode('utf-8')).decode('utf-8')

        data = {
            "random": key.decode("utf-8"),
            "username": encryption_func("Anonymous username"),
            "task": encryption_func(log_message),
            "company_name": encryption_func("Anonymous company name"),
            "local_drive_folder_location": encryption_func("Local Drive Folder Location Not Found !"),
            "date": date_time_encryption_text_func(key_name="%d %B, %Y"),
            "weekday": date_time_encryption_text_func(key_name="%A"),
            "time": date_time_encryption_text_func(key_name="%I:%M:%S %p")
        }

    if os.path.isfile(log_file_path):
        with open(log_file_path, 'r') as read_file:
            convert_to_list = json.loads(read_file.read())
            read_file.close()

        write_text = json.dumps(data)

        # convert list to json
        for item in convert_to_list:
            convert_to_json = json.dumps(item)
            write_text += f',\n{convert_to_json}'

        # text formatting
        final_write_text = f'[{write_text}]'
        # write log_info.json file
        with open(log_file_path, 'w') as write_file:
            write_file.write(final_write_text)
            write_file.close()
    else:
        write_data = f'[{json.dumps(data)}]'
        # write log_info.json file
        with open(log_file_path, 'w') as write_file:
            write_file.write(write_data)
            write_file.close()


# user input for show log file
def log_file_user_input():
    user_input_log_file_window = Toplevel(master=root)
    user_input_log_file_window.resizable(False, False)
    widget = Widget(master=user_input_log_file_window, frame_text="Input Correct Info :")
    log_file_path = widget.edit_text(label_text="Log File", row=0)
    log_file_path.insert(0, "Select your log_info.json file")
    log_file_path.bind(
        "<Button-1>", lambda a="Select log_info.json file", b="JSON File", c="log_info.json", d="True": file_select(
            log_file_path, a, b, c, d
        )
    )

    def checking_log_file_user_input() -> None:
        if is_empty(log_file_path) or field_value(log_file_path) == "Select your log_info.json file":
            log_file("Attempted to show log file with empty log file path field.", False)
            err_message_dialog(field_name="Log file path")
        else:
            log_file(f"Entered a valid log file path. Path : {field_value(log_file_path)}", False)
            show_log_file(log_file_path=field_value(log_file_path))
            user_input_log_file_window.destroy()

    widget.button(text="Submit", command=checking_log_file_user_input, row=1, col=1)
    widget.button(text="Close Window", command=user_input_log_file_window.destroy, row=1, col=2)


# Show Log file:
def show_log_file(log_file_path: str) -> None:
    show_log_file_window = Toplevel(master=root)
    show_log_file_window.resizable(False, False)
    show_log_file_window.geometry("860x600")

    buttons = LabelFrame(master=show_log_file_window, text="Click any Button :", padding=10)
    information = LabelFrame(master=show_log_file_window, text="Information :", padding=10)

    button_canvas = Canvas(buttons)
    button_canvas.pack(side=LEFT, fill=BOTH, expand=YES)
    y_scroll_bar = Scrollbar(master=buttons, orient=VERTICAL, command=button_canvas.yview)
    y_scroll_bar.pack(side=RIGHT, fill=Y)
    button_canvas.configure(yscrollcommand=y_scroll_bar.set)
    button_canvas.bind('<Configure>', lambda e: button_canvas.configure(scrollregion=button_canvas.bbox('all')))
    my_frame = Frame(button_canvas)
    button_canvas.create_window((0, 0), window=my_frame, anchor="nw")

    log_file_data = open(log_file_path, "r").read()
    all_log_info = json.loads(log_file_data)
    button_row = 0

    log_info_text = Label(master=information, text="Nothing to show!")
    log_info_text.grid(row=0, column=0)

    def show_values(output_data: str) -> None:
        log_info_text.config(text=output_data)

    def create_button(text: str, row: int, col: int, all_data: str) -> None:
        button = Button(master=my_frame, text=text, padding=5, command=lambda: show_values(all_data), width=30)
        button.grid(row=row, column=col, padx=5, pady=5)

    for x in all_log_info:
        log_data = read_log_file(log_data=x)

        data = f"Task: {log_data['task']}\nUsername: {log_data['username']}\n" \
            f"Company Name: {log_data['company_name']}\n" \
            f"Folder Location: {log_data['local_drive_folder_location']}\nDate: {log_data['date']}\n" \
            f"Weekday: {log_data['weekday']}\nTime: {log_data['time']}"

        serial_no = all_log_info.index(x) + 1
        if int(f"{serial_no / 3:.2f}"[-2]) == 3:
            create_button(
                text=f"{log_data['date']} {log_data['time']}",
                row=button_row,
                col=1,
                all_data=data
            )
        elif int(f"{serial_no / 3:.2f}"[-2]) == 6:
            create_button(
                text=f"{log_data['date']} {log_data['time']}",
                row=button_row,
                col=2,
                all_data=data
            )
        else:
            create_button(
                text=f"{log_data['date']} {log_data['time']}",
                row=button_row,
                col=3,
                all_data=data
            )
            button_row += 1

    buttons.pack(fill="both", expand=YES, padx=5, pady=5)
    information.pack(fill="both", expand=YES, padx=5, pady=5)
    log_file("Successfully displayed all log information", False)


# Read log file
def read_log_file(log_data: dict) -> dict:
    try:
        key = log_data["random"].encode('utf-8')
        cipher_code = Fernet(key)

        def decryption_func(key_name: str) -> str:
            return cipher_code.decrypt(bytes(log_data[key_name], 'utf-8')).decode('utf-8')

        return {
            "username": decryption_func(key_name="username"),
            "task": decryption_func(key_name="task"),
            "company_name": decryption_func(key_name="company_name"),
            "local_drive_folder_location": decryption_func(key_name="local_drive_folder_location"),
            "date": decryption_func(key_name="date"),
            "time": decryption_func(key_name="time"),

            "weekday": decryption_func(key_name="weekday")
        }
    except TypeError as e:
        log_file(f"Tried to open a wrong log file using this application.\nError : {e}", False)
        messagebox.showwarning("Invalid Log file", "Your Log file is Invalid.")


# Read setting file
def read_setting_file_func(
        path: str
) -> dict:
    setting_file_absolute_path = os.path.join(path, "setting.env")
    try:
        load_dotenv(setting_file_absolute_path)
        key = os.getenv('RANDOM').encode('utf-8')
        cipher_code = Fernet(key)

        # decryption shortcut function
        def decryption_func(key_name: str) -> str:
            return cipher_code.decrypt(bytes(os.getenv(key_name), 'utf-8')).decode('utf-8')

        try:
            data = {
                "key": key.decode('utf-8'),
                "username": decryption_func(key_name='ADMIN_USERNAME'),
                "file_name": decryption_func(key_name='FILE_NAME'),
                "company_name": decryption_func(key_name='COMPANY_NAME'),
                "vat_identifier": decryption_func(key_name='VAT_IDENTIFIER'),
                "total_identifier": decryption_func(key_name='TOTAL_IDENTIFIER'),
                "qr_loc_x": decryption_func(key_name='QR_LOC_X'),
                "qr_loc_y": decryption_func(key_name='QR_LOC_Y'),
                "qr_size": decryption_func(key_name='QR_SIZE'),
                "local_drive_folder_location": decryption_func(key_name='LOCAL_FILE_LOC'),
                "google_drive_access_token": decryption_func(key_name='GOOGLE_DRIVE_TOKEN'),
                "google_drive_folder_id": decryption_func(key_name='GOOGLE_DRIVE_FOLDER_ID'),
                "one_drive_folder": decryption_func(key_name='ONE_DRIVE_FOLDER'),
                "ftp_ip": decryption_func(key_name='FTP_IP'),
                "ftp_username": decryption_func(key_name='FTP_USERNAME'),
                "ftp_password": decryption_func(key_name='FTP_PASSWORD'),
                "ftp_folder_location": decryption_func(key_name='FTP_FOLDER_LOC')
            }
            return data
        except KeyError as e:
            log_file("Tried to processed using an invalid setting file.", False)
            messagebox.showerror("Value Not Found !", "Some value is missing in your setting file.")
            print(e)
            return {}
    except TypeError as e:
        log_file("Tried to processed using an invalid setting file.", False)
        messagebox.showerror("Value Not Found !", "Some Values not found in this setting file.\n"
                                                  "Please Create a new one.")
        print(f"Value Not Found !\n{e}")


# Create Statement button function
def create_statement() -> None:
    create_statement_file_input_window = Toplevel(master=root)
    create_statement_file_input_window.resizable(False, False)
    widget = Widget(master=create_statement_file_input_window, frame_text="Enter Correct Info :")

    setting_file_path = widget.edit_text(label_text="Setting File", row=0)
    setting_file_path.insert(0, "Select setting.env file")
    setting_file_path.bind(
        "<Button-1>", lambda a="Select setting.env file", b="Setting File", c="setting.env", d="False": file_select(
            setting_file_path, a, b, c, d
        )
    )

    pdf_file_path = widget.edit_text(label_text="PDF file", row=1)
    pdf_file_path.insert(0, "Select input PDF file")
    pdf_file_path.bind(
        "<Button-1>", lambda a="Select input PDF file", b="PDF files", c="*.pdf", d="True": file_select(
            pdf_file_path, a, b, c, d
        )
    )

    next_btn = widget.button(
        text="Next",
        command=lambda: checking_value(
            master=create_statement_file_input_window,
            widget=widget,
            setting_file_path=setting_file_path,
            pdf_file_path=pdf_file_path,
            next_button=next_btn,
            close_button=close_btn
        ),
        row=2,
        col=1
    )

    close_btn = widget.button(
        text="Close Window",
        command=create_statement_file_input_window.destroy,
        row=2,
        col=2
    )


def checking_value(
        master: Toplevel,
        widget: Widget,
        setting_file_path: Entry,
        pdf_file_path: Entry,
        next_button: Union[Button, Button],
        close_button: Union[Button, Button]
) -> None:
    global pdf_date, pdf_vat_number, hour, minute, second, year, day, month, total_amount, vat_amount
    if is_empty(setting_file_path):
        log_file("Attempted to create statement pdf file with empty setting file.", False)
        err_message_dialog(field_name="setting file's path")
    elif is_empty(pdf_file_path):
        log_file("Attempted to create statement pdf file with empty pdf file.", False)
        err_message_dialog(field_name="PDF file's path")
    else:
        set_config(field_name=setting_file_path, config="disabled")
        set_config(field_name=pdf_file_path, config="disabled")
        next_button.destroy()
        close_button.destroy()
        setting_data = read_setting_file_func(path=field_value(setting_file_path))
        # Read PDF file
        with open(field_value(pdf_file_path), 'rb') as read_pdf:
            pdf_page_obj = pdftotext.PDF(pdf_file=read_pdf)
        pdf_all_text = "\n\n".join(pdf_page_obj)
        pdf_page_text_list = pdf_all_text.split()
        try:
            # get date and vat number from pdf file
            pdf_date = list(filter(lambda item: date_rag.match(item), pdf_page_text_list))[0]
            pdf_vat_number = list(filter(lambda item: vat_num_rag.match(item), pdf_page_text_list))[0]
        except IndexError as e:
            print('Some value is missing in pdf file.', e)
            messagebox.showerror('Invalid Format', 'Your pdf file is Invalid Format.')

        try:
            vat_identifier_flag = False
            total_identifier_flag = False
            for x in pdf_page_text_list:
                if re.search(setting_data['vat_identifier'], x):
                    vat_identifier_flag = True
                elif re.search(setting_data['total_identifier'], x):
                    total_identifier_flag = True
                elif vat_identifier_flag:
                    if re.search(r"(\d+,)?\d+\.\d+", x):
                        vat_amount = re.search(r"(\d+,)?\d+\.\d+", x).group()
                        vat_identifier_flag = False
                    else:
                        continue
                elif total_identifier_flag:
                    if re.search(r"(\d+,)?\d+\.\d+", x):
                        total_amount = re.search(r"(\d+,)?\d+\.\d+", x).group()
                    else:
                        continue
        except IndexError as e:
            print(e)

        try:
            ntp_client = ntplib.NTPClient()
            response = ntp_client.request('pool.ntp.org', timeout=2)
            hour = str(datetime.fromtimestamp(response.tx_time).hour)
            minute = str(datetime.fromtimestamp(response.tx_time).minute)
            second = str(datetime.fromtimestamp(response.tx_time).second)
        except ntplib.NTPException as e:
            hour = str(datetime.fromtimestamp(time.time()).hour)
            minute = str(datetime.fromtimestamp(time.time()).minute)
            second = str(datetime.fromtimestamp(time.time()).second)
            print(f'Tried using NTP server but it was not reachable so instead used system time\nError: {e}')

        # formatting time
        def check_digit(digit: str) -> str:
            return f'0{digit}' if len(digit) < 2 else digit

        # final time output
        hour = check_digit(hour)
        minute = check_digit(minute)
        second = check_digit(second)

        # checking info
        date_time = datetime.now()
        if pdf_date is not None:
            date_data = pdf_date.split(re.findall(r'[./-]', pdf_date)[0])
            try:
                year = list(filter(lambda a: re.search(r'[0-9]{4}', a), date_data))[0]
            except IndexError as e:
                year = f"20{list(filter(lambda a: re.search(r'[0-9]{2}', a), date_data))[2]}"
                print(e)
            day = date_data[0]

            try:
                month_list = list(calendar.month_abbr)
                lower_date = pdf_date.lower()
                month_index = str(month_list.index(
                    list(filter(lambda a: re.findall(a.lower(), lower_date), month_list[1:]))[0]
                ))
                month_index = check_digit(month_index)
            except IndexError as e:
                month_index = date_data[1]
                print(e)
            pdf_date = f'{year}-{month_index}-{day} {hour}:{minute}:{second}'
        else:
            pdf_date = date_time.strftime(f'%Y-%m-%d {hour}:{minute}:{second}')

        widget.label(label_text=f"Company Name: {setting_data['company_name']}", row=2, col=1)
        widget.label(label_text=f"Date: {pdf_date}", row=3, col=1)
        widget.label(label_text=f"VAT Number : {pdf_vat_number}", row=4, col=1)
        widget.label(label_text=f"Total: {total_amount}", row=5, col=1)
        widget.label(label_text=f"VAT: {vat_amount}", row=6, col=1)
        widget.label(label_text=f"QR Location X (cm): {setting_data['qr_loc_x']}", row=7, col=1)
        widget.label(label_text=f"QR Location Y (cm): {setting_data['qr_loc_y']}", row=8, col=1)
        widget.label(label_text=f"QR Code Size (cm): {setting_data['qr_size']}", row=9, col=1)

        # Prepare QR Code
        def prepare_result_file() -> None:
            global qr_text
            qr_text = TLV()
            qr_text[0x01] = setting_data["company_name"].encode('UTF-8')
            qr_text[0x02] = pdf_vat_number.encode('UTF-8')
            qr_text[0x03] = pdf_date.encode('UTF-8')
            qr_text[0x04] = total_amount.encode('UTF-8')
            qr_text[0x05] = vat_amount.encode('UTF-8')
            qr_text = base64.b64encode(qr_text.to_byte_array())
            qr_code = qrcode.QRCode(
                version=2,
                box_size=25,
                border=5
            )
            qr_code.add_data(data=qr_text)
            qr_code.make(fit=True)
            image = qr_code.make_image(fill='black')
            image_path = os.path.join(os.path.dirname(field_value(pdf_file_path)), 'qr_code.png')
            qr_code_pdf_file_path = os.path.join(os.path.dirname(field_value(pdf_file_path)), 'qr_code.pdf')
            pdf = canvas.Canvas(qr_code_pdf_file_path)
            image.save(image_path)
            pdf.drawImage(
                image=image_path,
                x=int(setting_data["qr_loc_x"]) * 37.79,
                y=int(setting_data["qr_loc_y"]) * 37.79,
                width=int(setting_data["qr_size"]) * 37.79,
                height=int(setting_data["qr_size"]) * 37.79,
                preserveAspectRatio=True,
                mask='auto'
            )
            pdf.save()

            # read qr_code.pdf file
            f = open(qr_code_pdf_file_path, 'rb')
            qr_code_file = PdfFileReader(f)

            # output file ready
            output_file = PdfFileWriter()
            input_pdf_file = open(field_value(pdf_file_path), 'rb')
            input_pdf_file_read = PdfFileReader(input_pdf_file)

            # get number of page in document
            page_count = input_pdf_file_read.getNumPages()

            # Go through all the input file pages to add a QrCode to them
            for page_number in range(page_count):
                # merge the QrCode with the page
                input_page = input_pdf_file_read.getPage(page_number)
                input_page.mergePage(qr_code_file.getPage(0))
                # add page from input file to output document
                output_file.addPage(input_page)
                # finally, write "output" to document-output.pdf
            output_file_name = os.path.join(
                os.path.dirname(field_value(pdf_file_path)),
                f'{Path(field_value(pdf_file_path)).stem}-QR.pdf'
            )
            with open(output_file_name, "wb") as outputStream:
                output_file.write(outputStream)
            f.close()
            input_pdf_file.close()
            os.remove(image_path)
            os.remove(qr_code_pdf_file_path)
            messagebox.showinfo(
                title="Successfully created !",
                message=f"Successfully Created a statement file !\nPath: {output_file_name}"
            )
            log_file(
                log_message=f"Successfully created a new statement {output_file_name} file.",
                setting_file_path=field_value(setting_file_path)
            )
            upload_google_drive(file_path=output_file_name, setting_file_path=field_value(setting_file_path))
            upload_one_drive(file_path=output_file_name, setting_file_path=field_value(setting_file_path))
            upload_ftp_server(file_path=output_file_name, setting_file_path=field_value(setting_file_path))
            master.destroy()

        widget.button(
            text="Submit",
            command=prepare_result_file,
            row=10,
            col=1
        )

        widget.button(
            text="Close Window",
            command=master.destroy,
            row=10,
            col=2
        )


# Google Drive upload file function
def upload_google_drive(file_path: str, setting_file_path: str) -> None:
    setting_data = read_setting_file_func(path=setting_file_path)
    if setting_data["google_drive_access_token"] != "" and setting_data["google_drive_folder_id"] != "":
        try:
            headers = {"Authorization": f"Bearer {setting_data['google_drive_access_token']}"}
            para = {
                "name": os.path.basename(file_path),
                "parents": [setting_data["google_drive_folder_id"]]
            }
            files = {
                'data': ('metadata', json.dumps(para), 'application/json; charset=UTF-8'),
                'file': open(file_path, "rb")
            }
            r = requests.post(
                "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
                headers=headers,
                files=files
            )
            messagebox.showinfo('Successfully Uploaded to Google Drive', r.text)
            log_file(log_message=f"{file_path} Uploaded to Google Drive.", setting_file_path=setting_file_path)
        except Exception as e:
            log_file(log_message=f"{file_path} couldn't Upload to Google Drive.", setting_file_path=setting_file_path)
            messagebox.showwarning('Error!', 'Your Google drive access token or Google drive folder ID Invalid.')
            print(e)
    else:
        pass


# OneDrive Upload file function.
def upload_one_drive(file_path: str, setting_file_path: str) -> None:
    setting_data = read_setting_file_func(path=setting_file_path)
    if setting_data["one_drive_folder"] != "":
        read_file = open(file_path, "rb")
        file_text = read_file.read()
        one_drive_path = os.path.join(setting_data["one_drive_folder"], os.path.basename(file_path))
        try:
            with open(one_drive_path, "wb") as write_file:
                write_file.write(file_text)
            log_file(log_message="Successfully Uploaded to OneDrive Folder", setting_file_path=setting_file_path)
            messagebox.showinfo(
                title="Successfully Uploaded to OneDrive",
                message=f"Successfully Uploaded to OneDrive Folder.\nPath: {one_drive_path}"
            )
        except Exception as e:
            messagebox.showerror("Error!", "The OneDrive you specified is not available.")
            log_file(
                log_message=f"{file_path} could not save file to OneDrive. Because OneDrive Folder is not accessible",
                setting_file_path=setting_file_path
            )
            print(e)
    else:
        pass


# Upload to FTP Server function.
def upload_ftp_server(file_path: str, setting_file_path: str) -> None:
    setting_data = read_setting_file_func(path=setting_file_path)
    if setting_data['ftp_ip'] != "" and setting_data['ftp_username'] != "" and setting_data['ftp_password'] != "":
        try:
            session = ftplib.FTP(setting_data['ftp_ip'])
            if session.login(user=setting_data['ftp_username'], passwd=setting_data['ftp_password']):
                save_location = os.path.join(setting_data['ftp_folder_location'], os.path.basename(file_path))
                file_text = open(file_path, "rb")
                ftp_command = f"STOR {save_location}"
                session.storbinary(ftp_command, file_text)
                session.quit()
                log_file(
                    log_message=f"{file_path} is successfully uploaded to FTP server",
                    setting_file_path=setting_file_path
                )
                messagebox.showinfo(
                    title="Successfully Upload!",
                    message=f"{file_path} is successfully uploaded to FTP server"
                )
            else:
                log_file(
                    log_message='App can not access to the FTP Server, Because wrong password or username',
                    setting_file_path=setting_file_path
                )
                messagebox.showerror("Wrong Data", "Wrong FTP username of password !")
        except ValueError as e:
            log_file(
                log_message=f"{file_path} could not save file to FTP Server. Because FTP info is not correct.",
                setting_file_path=setting_file_path
            )
            print(e)
            messagebox.showerror("Error!", "FTP server info is not correct")
    else:
        pass


if __name__ == "__main__":
    root = Tk()
    root.title("QR Invoice APP")
    root.resizable(False, False)
    date_rag = re.compile(r"^([0-9]+|[A-Za-z]+)[/. -]([0-9]+|[A-Za-z]+)[/. -]([0-9]+|[A-Za-z]+)$")
    vat_num_rag = re.compile(r"(^[3]([0-9]{14}$))")
    pdf_date = None
    pdf_vat_number = None
    total_amount = None
    vat_amount = None
    hour = None
    minute = None
    second = None
    year = None
    day = None
    month = None
    vat = str()
    total = str()
    qr_text = None
    language_choice()
    root.mainloop()

