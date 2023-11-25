import os
import requests
import tkinter as tk
from tkinter import ttk, filedialog
import threading


class ScanThread(threading.Thread):
    def __init__(self, files, api_key, update_callback, error_callback, response_callback,complete_callback):
        super().__init__()
        self.files = files
        self.api_key = api_key
        self.update_callback = update_callback
        self.error_callback = error_callback
        self.response_callback = response_callback
        self.complete_callback = complete_callback

    def is_valid_api_key(self, file):
        # Test request to a non-authenticated VirusTotal API endpoint
        try:
            url = "https://www.virustotal.com/api/v3/files"
            files = {"file": (file, open(file, "rb"), "text/plain")}
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_key
            }

            response = requests.post(url, files=files, headers=headers)
            response.raise_for_status()  # Raise an exception if the response status code is not 200
            return True
        except requests.exceptions.HTTPError as e:
            self.response_callback(response)
            print(response)
            # Handle HTTP errors and display a message to the user
            self.error_callback(f"HTTP Error: {e}")
            return False
        except Exception as e:
            # Handle other errors and display a message to the user
            self.error_callback(f"Error: {e}")
            return False

    def run(self):
        try:
            for file in self.files:
                if self.is_valid_api_key(file):
                    result = self.check_file(file)
                    self.update_callback(result, file)
                else:
                    self.error_callback(f"Check response info via " + "https://docs.virustotal.com/reference/errors" + "\nto open the link use cmd")
                    print(f"Check response info via " + "https://docs.virustotal.com/reference/errors")
                    return
            self.complete_callback("Scan completed.")
        except Exception as e:
            self.error_callback(f"Unexpected error: {str(e)}")

    def Scan_id(self, file):
        url = "https://www.virustotal.com/api/v3/files"
        files = {"file": (file, open(file, "rb"), "text/plain")}
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

        response = requests.post(url, files=files, headers=headers)

        result = response.json()
        scan_id = result.get('data', {}).get('id')
        if scan_id:
            return scan_id
        else:
            raise ValueError("Failed to retrieve scan ID from the response.")
        
    def check_file(self, file_path):
        try:
            Id = self.Scan_id(file_path)
            url = f"https://www.virustotal.com/api/v3/analyses/{Id}"
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_key
            }
            response = requests.get(url, headers=headers)

            # Process the response to check if the file is malicious
            result = response.json()

            data = result["data"]

            attributes = data["attributes"]

            stats = attributes["stats"]

            malicious_count = stats["malicious"]

            if malicious_count > 0:
                return "Malicious"
            else:
                return "Clean"
        except requests.exceptions.HTTPError as err:
            print(f"HTTP Error: {err}")
            return "Error"
        except requests.exceptions.RequestException as err:
            print(f"Request Exception: {err}")
            return "Error"
        except Exception as err:
            print(f"Unexpected error occurred: {err}")
            return "Error"





class DirectoryScanner:
    def __init__(self, master):
        # Initialize the class with the main window
        self.master = master
        self.master.title('Directory Scanner')
        self.master.geometry("400x300")  # Set initial window size

        # Variables to store folder, API key, and scan status
        self.folder_var = tk.StringVar()
        self.api_key_var = tk.StringVar()
        self.scan_response_var = tk.StringVar()
        self.scan_status_var = tk.StringVar()

        # Create a menu bar
        self.menu_bar = tk.Menu(self.master)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.master.config(menu=self.menu_bar)

        # Create a frame for organizing GUI components
        self.frame = ttk.Frame(self.master, padding=(10, 10, 10, 10))
        self.frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(0, weight=1)

        # Label and entry for selecting a folder
        ttk.Label(self.frame, text="Select Folder:").grid(row=0, column=0, pady=10, sticky=tk.W)
        self.folder_entry = ttk.Entry(self.frame, textvariable=self.folder_var, state='disabled', width=40)
        self.folder_entry.grid(row=1, column=0, pady=5, padx=10, sticky=tk.W)

        # Button to browse and select a folder
        ttk.Button(self.frame, text="Browse", command=self.select_directory).grid(row=1, column=1, pady=10, sticky=tk.W)
        
        # Label to display folder and subfolder count
        self.folder_count_label = ttk.Label(self.frame, text='')
        self.folder_count_label.grid(row=2, column=0, pady=5, padx=10, sticky=tk.W)

        # Label and entry for entering VirusTotal API key
        # ttk.Label(self.frame, text="VirusTotal API Key:").grid(row=5, column=0, pady=5, sticky=tk.W)
        # self.api_key_entry = ttk.Entry(self.frame, textvariable=self.api_key_var)
        # self.api_key_entry.grid(row=6, column=0, pady=10, padx=10, sticky=tk.W)
        self.api_key_var.set("16fe085c26136d98480f1c18f0d22b2e42c9ab81b500cd5be2477ec82ce69a47")

        # Button to start the scan
        ttk.Button(self.frame, text="Scan Directory", command=self.scan_directory).grid(row=7, column=0, pady=10, sticky=tk.W)

        # Label to display the scan status
        self.status_label = ttk.Label(self.frame, textvariable=self.scan_status_var)
        self.status_label.grid(row=9, column=0, pady=2, sticky=tk.W)
        # Label to display the scan response
        self.status_label = ttk.Label(self.frame, textvariable=self.scan_response_var)
        self.status_label.grid(row=8, column=0, pady=2, sticky=tk.W)

    def select_directory(self):
        # Prompt the user to select a directory
        directory = filedialog.askdirectory()

        if directory:
            # Set the selected directory in the read-only entry widget
            self.folder_var.set(directory)
            
            # Get the files and subdirectories in the selected directory
            files, subdirectories = self.get_files_and_subdirectories(directory)

             # Update the status label with the number of files and subdirectories
            num_files = len(files)
            num_subdirectories = len(subdirectories)
            status_text = f'{num_files} files and {num_subdirectories} subdirectories found'
            self.status_label.config(text=status_text)

            # Count the number of folders and subfolders
            unique_folders = set(os.path.relpath(os.path.dirname(file), directory) for file in files)
            num_folders = len(unique_folders)
            num_subfolders = len(set(subdirectories))

            # Display the folder and subfolder count
            count_text = f'{num_folders} folders and {num_subfolders} subfolders'
            self.folder_count_label.config(text=count_text)

    def scan_directory(self):
        api_key = self.api_key_var.get()
        directory = self.folder_var.get()

        if not directory and not api_key:
            self.scan_status_var.set("Please select a folder and enter your VirusTotal API key.")
            return
        elif not api_key:
            self.scan_status_var.set("Please enter a VirusTotal API key.")
            return
        elif not directory:
            self.scan_status_var.set("Please select a folder.")
            return

        files, _ = self.get_files_and_subdirectories(directory)

        def update_status(result, file):
            status_text = f'{os.path.basename(file)}: {result}'
            self.scan_status_var.set(status_text)

        def show_error(error_message):
            self.scan_status_var.set(error_message)
        
        def show_response(error_message):
            self.scan_response_var.set(error_message)

        def scan_complete(message):
            self.scan_status_var.set(message)

        scan_thread = ScanThread(files, api_key, update_status, show_error, show_response, scan_complete)
        scan_thread.start()


    def get_files_and_subdirectories(self, directory):
        files = []
        subdirectories = []

        for root, dirs, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                files.append(file_path)

            for subdir in dirs:
                subdirectory_path = os.path.join(root, subdir)
                subdirectories.append(subdirectory_path)

        return files, subdirectories

# Create a Tkinter window and start the main event loop
root = tk.Tk()
app = DirectoryScanner(root)
root.mainloop()