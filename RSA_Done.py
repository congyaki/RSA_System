import tkinter as tk
from tkinter import filedialog, messagebox
import rsa
import hashlib
import os
from tkinter.ttk import Progressbar
import threading

class RSACryptosystemApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Cryptosystem")
        # self.root.geometry("1120x550")
        # Khởi tạo biến lưu key
        self.public_key = None
        self.private_key = None

       # Khung tạo key
        key_frame = tk.LabelFrame(root, text="Tạo Key")
        key_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # Row 0 for key length input
        tk.Label(key_frame, text="Độ dài Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.key_length_var = tk.StringVar(value="1024")
        tk.Entry(key_frame, textvariable=self.key_length_var, width=10).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(key_frame, text="Tạo Key Tự Động", command=self.generate_key).grid(row=0, column=2, padx=5, pady=5)

        # Row 1 for public/private key buttons
        tk.Button(key_frame, text="Mở Public Key", command=self.open_public_key).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        tk.Button(key_frame, text="Mở Private Key", command=self.open_private_key).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Adjust column weights for dynamic resizing
        key_frame.grid_columnconfigure(0, weight=1)
        key_frame.grid_columnconfigure(1, weight=1)
        key_frame.grid_columnconfigure(2, weight=1)


        # Khung thông tin key
        key_info_frame = tk.LabelFrame(root, text="Thông tin Key")
        key_info_frame.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        tk.Label(key_info_frame, text="Module N:").grid(row=0, column=0)
        self.modulus_var = tk.StringVar()
        tk.Entry(key_info_frame, textvariable=self.modulus_var, width=50).grid(row=0, column=1)

        tk.Label(key_info_frame, text="Mũ Mã Hóa (E):").grid(row=1, column=0)
        self.public_exp_var = tk.StringVar()
        tk.Entry(key_info_frame, textvariable=self.public_exp_var, width=50).grid(row=1, column=1)

        tk.Label(key_info_frame, text="Mũ Giải Mã (D):").grid(row=2, column=0)
        self.private_exp_var = tk.StringVar()
        tk.Entry(key_info_frame, textvariable=self.private_exp_var, width=50).grid(row=2, column=1)

        # Khung mã hóa và giải mã
        encrypt_frame = tk.LabelFrame(root, text="Mã hóa và Giải mã")
        encrypt_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        tk.Label(encrypt_frame, text="Đầu vào:").grid(row=0, column=0)
        self.input_file_var = tk.StringVar()
        tk.Entry(encrypt_frame, textvariable=self.input_file_var, width=50).grid(row=0, column=1)
        tk.Button(encrypt_frame, text="Chọn file", command=self.select_input_file).grid(row=0, column=2)

        tk.Label(encrypt_frame, text="Đầu ra:").grid(row=1, column=0)
        self.output_file_var = tk.StringVar()
        tk.Entry(encrypt_frame, textvariable=self.output_file_var, width=50).grid(row=1, column=1)
        tk.Button(encrypt_frame, text="Chọn thư mục", command=self.select_output_folder).grid(row=1, column=2)

        tk.Button(encrypt_frame, text="Mã hóa", command=self.encrypt_file).grid(row=2, column=1)
        tk.Button(encrypt_frame, text="Giải mã", command=self.decrypt_file).grid(row=2, column=2)


        # Khung kiểm tra hash file
        hash_frame = tk.LabelFrame(root, text="Kiểm Tra File")
        hash_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

        # Chọn file 1 và file 2
        file_selection_frame = tk.Frame(hash_frame)
        file_selection_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5)

        tk.Label(file_selection_frame, text="File 1:").grid(row=0, column=0, sticky="w")
        self.file_to_hash1_var = tk.StringVar()
        tk.Entry(file_selection_frame, textvariable=self.file_to_hash1_var, width=50).grid(row=0, column=1, padx=5)
        tk.Button(file_selection_frame, text="Mở File 1", command=self.select_file_to_hash1).grid(row=0, column=2, padx=5)

        tk.Label(file_selection_frame, text="File 2:").grid(row=1, column=0, sticky="w")
        self.file_to_hash2_var = tk.StringVar()
        tk.Entry(file_selection_frame, textvariable=self.file_to_hash2_var, width=50).grid(row=1, column=1, padx=5)
        tk.Button(file_selection_frame, text="Mở File 2", command=self.select_file_to_hash2).grid(row=1, column=2, padx=5)

        # Nút kiểm tra
        check_button_frame = tk.Frame(hash_frame)
        check_button_frame.grid(row=1, column=0, columnspan=3, pady=5)

        tk.Button(check_button_frame, text="Kiểm Tra", command=self.compute_hash, width=20).pack(pady=5)

        # Hiển thị kết quả hash file
        tk.Label(hash_frame, text="MD5:", anchor="w").grid(row=2, column=0, sticky="w", padx=10)
        tk.Label(hash_frame, text="SHA-1:", anchor="w").grid(row=3, column=0, sticky="w", padx=10)
        tk.Label(hash_frame, text="SHA-256:", anchor="w").grid(row=4, column=0, sticky="w", padx=10)

        # Kết quả hash file 1
        self.md5_file1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.md5_file1_var, width=40, state="readonly").grid(row=2, column=1, padx=5)
        self.sha1_file1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha1_file1_var, width=40, state="readonly").grid(row=3, column=1, padx=5)
        self.sha256_file1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha256_file1_var, width=40, state="readonly").grid(row=4, column=1, padx=5)

        # Kết quả hash file 2
        self.md5_file2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.md5_file2_var, width=40, state="readonly").grid(row=2, column=2, padx=5)
        self.sha1_file2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha1_file2_var, width=40, state="readonly").grid(row=3, column=2, padx=5)
        self.sha256_file2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha256_file2_var, width=40, state="readonly").grid(row=4, column=2, padx=5)

        # Kết quả so sánh
        tk.Label(hash_frame, text="Kết quả so sánh:").grid(row=5, column=0, sticky="w", padx=10)
        self.compare_result_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.compare_result_var, width=80, state="readonly").grid(row=5, column=1, columnspan=2, padx=5)


        # Thêm thanh tiến trình vào khung mã hóa và giải mã
        self.progress_var = tk.DoubleVar()
        self.progress_bar = Progressbar(encrypt_frame, variable=self.progress_var, maximum=100, length=200)
        self.progress_bar.grid(row=3, column=1, columnspan=2, pady=10)


    def select_file_to_hash1(self):
        file_path = filedialog.askopenfilename()
        self.file_to_hash1_var.set(file_path)

    def select_file_to_hash2(self):
        file_path = filedialog.askopenfilename()
        self.file_to_hash2_var.set(file_path)

    def compute_hash(self):
        # Hash file 1
        file1_path = self.file_to_hash1_var.get()
        if file1_path and os.path.exists(file1_path):
            with open(file1_path, 'rb') as f:
                data = f.read()
            md5_file1 = hashlib.md5(data).hexdigest()
            sha1_file1 = hashlib.sha1(data).hexdigest()
            sha256_file1 = hashlib.sha256(data).hexdigest()
            self.md5_file1_var.set(md5_file1)
            self.sha1_file1_var.set(sha1_file1)
            self.sha256_file1_var.set(sha256_file1)
        else:
            self.compare_result_var.set("File 1 không hợp lệ")
            return

        # Hash file 2
        file2_path = self.file_to_hash2_var.get()
        if file2_path and os.path.exists(file2_path):
            with open(file2_path, 'rb') as f:
                data = f.read()
            md5_file2 = hashlib.md5(data).hexdigest()
            sha1_file2 = hashlib.sha1(data).hexdigest()
            sha256_file2 = hashlib.sha256(data).hexdigest()
            self.md5_file2_var.set(md5_file2)
            self.sha1_file2_var.set(sha1_file2)
            self.sha256_file2_var.set(sha256_file2)
        else:
            self.compare_result_var.set("File 2 không hợp lệ")
            return

        # So sánh hash
        if md5_file1 == md5_file2 and sha1_file1 == sha1_file2 and sha256_file1 == sha256_file2:
            self.compare_result_var.set("Hai file giống nhau!")
        else:
            self.compare_result_var.set("Hai file KHÔNG giống nhau!")

    def generate_key(self):
        try:
            key_length = int(self.key_length_var.get())
            (self.public_key, self.private_key) = rsa.newkeys(key_length)

            # Cập nhật thông tin key
            self.modulus_var.set(str(self.public_key.n))
            self.public_exp_var.set(str(self.public_key.e))
            self.private_exp_var.set(str(self.private_key.d))

            # Cho phép người dùng chọn thư mục lưu key
            folder_path = filedialog.askdirectory()
            if not folder_path:
                messagebox.showwarning("Warning", "Không có thư mục nào được chọn, khóa sẽ không được lưu.")
                return

            # Lưu public key
            public_key_path = os.path.join(folder_path, "public_key.pem")
            with open(public_key_path, 'wb') as pub_file:
                pub_file.write(self.public_key.save_pkcs1('PEM'))

            # Lưu private key
            private_key_path = os.path.join(folder_path, "private_key.pem")
            with open(private_key_path, 'wb') as priv_file:
                priv_file.write(self.private_key.save_pkcs1('PEM'))

            messagebox.showinfo("Success", f"Khóa RSA đã được tạo và lưu thành công !\nPublic key: {public_key_path}\nPrivate key: {private_key_path}")

        except ValueError:
            messagebox.showerror("Error", "Độ dài khóa không hợp lệ !")

    def open_public_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    self.public_key = rsa.PublicKey.load_pkcs1(f.read(), format='PEM')
                self.modulus_var.set(str(self.public_key.n))
                self.public_exp_var.set(str(self.public_key.e))
                messagebox.showinfo("Success", "Khóa công khai đã được tải thành công !")
            except Exception as e:
                messagebox.showerror("Error", f"Không tải được khóa công khai: {str(e)}")

    def open_private_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    self.private_key = rsa.PrivateKey.load_pkcs1(f.read(), format='PEM')
                self.modulus_var.set(str(self.private_key.n))
                self.private_exp_var.set(str(self.private_key.d))
                messagebox.showinfo("Success", "Khóa riêng tư đã được tải thành công !")
            except Exception as e:
                messagebox.showerror("Error", f"Không tải được khóa riêng tư: {str(e)}")

    def select_input_file(self):
        file_path = filedialog.askopenfilename()
        self.input_file_var.set(file_path)

    def select_output_folder(self):
        folder_path = filedialog.askdirectory()
        self.output_file_var.set(folder_path)

    def encrypt_file(self):
        def worker():
            input_file = self.input_file_var.get()
            if not input_file or not os.path.exists(input_file):
                messagebox.showerror("Error", "Tệp đầu vào không hợp lệ !")
                return

            try:
                with open(input_file, 'rb') as f:
                    data = f.read()

                original_filename = os.path.basename(input_file)
                max_chunk_size = (self.public_key.n.bit_length() // 8) - 11
                encrypted_chunks = []

                # Reset progress bar
                self.progress_var.set(0)
                total_chunks = len(data) // max_chunk_size + (1 if len(data) % max_chunk_size != 0 else 0)

                for i in range(0, len(data), max_chunk_size):
                    chunk = data[i:i + max_chunk_size]
                    encrypted_chunk = rsa.encrypt(chunk, self.public_key)
                    encrypted_chunks.append(encrypted_chunk)

                    # Cập nhật thanh tiến trình
                    self.progress_var.set((i // max_chunk_size + 1) / total_chunks * 100)
                    self.root.update_idletasks()

                encrypted_data = b''.join(encrypted_chunks)
                encrypted_data_with_filename = original_filename.encode() + b'\0' + encrypted_data

                output_file = os.path.join(self.output_file_var.get(), "encrypted_file")
                with open(output_file, 'wb') as f:
                    f.write(encrypted_data_with_filename)

                messagebox.showinfo("Success", "Tập tin đã được mã hóa thành công !")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.progress_var.set(100)

        # Tạo và chạy luồng riêng
        threading.Thread(target=worker, daemon=True).start()

    def decrypt_file(self):
        def worker():
            input_file = self.input_file_var.get()
            if not input_file or not os.path.exists(input_file):
                messagebox.showerror("Error", "Tệp đầu vào không hợp lệ !")
                return

            try:
                with open(input_file, 'rb') as f:
                    encrypted_data_with_filename = f.read()

                original_filename, encrypted_data = encrypted_data_with_filename.split(b'\0', 1)
                max_chunk_size = (self.private_key.n.bit_length() // 8)
                decrypted_chunks = []

                # Reset progress bar
                self.progress_var.set(0)
                total_chunks = len(encrypted_data) // max_chunk_size + (1 if len(encrypted_data) % max_chunk_size != 0 else 0)

                for i in range(0, len(encrypted_data), max_chunk_size):
                    chunk = encrypted_data[i:i + max_chunk_size]
                    decrypted_chunk = rsa.decrypt(chunk, self.private_key)
                    decrypted_chunks.append(decrypted_chunk)

                    # Cập nhật thanh tiến trình
                    self.progress_var.set((i // max_chunk_size + 1) / total_chunks * 100)
                    self.root.update_idletasks()

                decrypted_data = b''.join(decrypted_chunks)
                original_filename_str = original_filename.decode()
                filename, ext = os.path.splitext(original_filename_str)
                output_file = os.path.join(self.output_file_var.get(), f"{filename}_after_decrypt{ext}")

                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)

                messagebox.showinfo("Success", f"Tập tin đã được giải mã thành công !\nĐược lưu ở {output_file}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.progress_var.set(100)  # Đặt thanh tiến trình hoàn thành
            
        # Tạo và chạy luồng riêng
        threading.Thread(target=worker, daemon=True).start()

    def select_file_to_hash(self):
        file_path = filedialog.askopenfilename()
        self.file_to_hash_var.set(file_path)

    # def compute_hash(self):
    #     file_path = self.file_to_hash_var.get()
    #     if not file_path or not os.path.exists(file_path):
    #         messagebox.showerror("Error", "Invalid file")
    #         return

    #     with open(file_path, 'rb') as f:
    #         data = f.read()

    #     self.md5_var.set(hashlib.md5(data).hexdigest())
    #     self.sha1_var.set(hashlib.sha1(data).hexdigest())
    #     self.sha256_var.set(hashlib.sha256(data).hexdigest())

if __name__ == "__main__":
    root = tk.Tk()
    app = RSACryptosystemApp(root)
    root.mainloop()
