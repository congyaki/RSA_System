import tkinter as tk
from tkinter import filedialog, messagebox
import rsa
import hashlib
import os

class RSACryptosystemApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Cryptosystem")

        # Khởi tạo biến lưu key
        self.public_key = None
        self.private_key = None

        # Khung tạo key
        key_frame = tk.LabelFrame(root, text="Tạo Key")
        key_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        tk.Label(key_frame, text="Độ dài Key:").grid(row=0, column=0)
        self.key_length_var = tk.StringVar(value="1024")
        tk.Entry(key_frame, textvariable=self.key_length_var, width=10).grid(row=0, column=1)
        tk.Button(key_frame, text="Tạo Key Tự Động", command=self.generate_key).grid(row=0, column=2)
        tk.Button(key_frame, text="Open Public Key", command=self.open_public_key).grid(row=1, column=1)
        tk.Button(key_frame, text="Open Private Key", command=self.open_private_key).grid(row=1, column=2)

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
        encrypt_frame = tk.LabelFrame(root, text="Mã Hóa và Giải Mã")
        encrypt_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        tk.Label(encrypt_frame, text="Input:").grid(row=0, column=0)
        self.input_file_var = tk.StringVar()
        tk.Entry(encrypt_frame, textvariable=self.input_file_var, width=50).grid(row=0, column=1)
        tk.Button(encrypt_frame, text="Select File", command=self.select_input_file).grid(row=0, column=2)

        tk.Label(encrypt_frame, text="Output:").grid(row=1, column=0)
        self.output_file_var = tk.StringVar()
        tk.Entry(encrypt_frame, textvariable=self.output_file_var, width=50).grid(row=1, column=1)
        tk.Button(encrypt_frame, text="Select Folder", command=self.select_output_folder).grid(row=1, column=2)

        tk.Button(encrypt_frame, text="Mã Hóa", command=self.encrypt_file).grid(row=2, column=1)
        tk.Button(encrypt_frame, text="Giải Mã", command=self.decrypt_file).grid(row=2, column=2)


        # Khung kiểm tra hash file
        hash_frame = tk.LabelFrame(root, text="Kiểm Tra File")
        hash_frame.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # Chọn file 1
        tk.Label(hash_frame, text="File gốc:").grid(row=0, column=0)
        self.file_to_hash1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.file_to_hash1_var, width=50).grid(row=0, column=1)
        tk.Button(hash_frame, text="Open File gốc", command=self.select_file_to_hash1).grid(row=0, column=2)

        # Chọn file 2
        tk.Label(hash_frame, text="File đã giải mã:").grid(row=1, column=0)
        self.file_to_hash2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.file_to_hash2_var, width=50).grid(row=1, column=1)
        tk.Button(hash_frame, text="Open File đã giải mã", command=self.select_file_to_hash2).grid(row=1, column=2)

        # Nút kiểm tra
        tk.Button(hash_frame, text="Kiểm Tra", command=self.compute_hash).grid(row=2, column=1, columnspan=2)

        # Tiêu đề cột cho "File gốc" và "File đã giải mã"
        tk.Label(hash_frame, text="File gốc").grid(row=3, column=1)
        tk.Label(hash_frame, text="File đã giải mã").grid(row=3, column=2)

        # Hiển thị kết quả hash file
        tk.Label(hash_frame, text="MD5:").grid(row=4, column=0)
        tk.Label(hash_frame, text="SHA-1:").grid(row=5, column=0)
        tk.Label(hash_frame, text="SHA-256:").grid(row=6, column=0)

        # Hiển thị kết quả hash file 1
        self.md5_file1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.md5_file1_var, width=50, state="readonly").grid(row=4, column=1)
        self.sha1_file1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha1_file1_var, width=50, state="readonly").grid(row=5, column=1)
        self.sha256_file1_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha256_file1_var, width=50, state="readonly").grid(row=6, column=1)

        # Hiển thị kết quả hash file 2
        self.md5_file2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.md5_file2_var, width=50, state="readonly").grid(row=4, column=2)
        self.sha1_file2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha1_file2_var, width=50, state="readonly").grid(row=5, column=2)
        self.sha256_file2_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.sha256_file2_var, width=50, state="readonly").grid(row=6, column=2)

        # Hiển thị kết quả so sánh
        tk.Label(hash_frame, text="Kết Quả So Sánh:").grid(row=7, column=0)
        self.compare_result_var = tk.StringVar()
        tk.Entry(hash_frame, textvariable=self.compare_result_var, width=50, state="readonly").grid(row=7, column=1, columnspan=2)


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
                messagebox.showwarning("Warning", "No folder selected, keys will not be saved.")
                return

            # Lưu public key
            public_key_path = os.path.join(folder_path, "public_key.pem")
            with open(public_key_path, 'wb') as pub_file:
                pub_file.write(self.public_key.save_pkcs1('PEM'))

            # Lưu private key
            private_key_path = os.path.join(folder_path, "private_key.pem")
            with open(private_key_path, 'wb') as priv_file:
                priv_file.write(self.private_key.save_pkcs1('PEM'))

            messagebox.showinfo("Success", f"RSA Key generated and saved successfully!\nPublic key: {public_key_path}\nPrivate key: {private_key_path}")

        except ValueError:
            messagebox.showerror("Error", "Invalid key length")

    def open_public_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    self.public_key = rsa.PublicKey.load_pkcs1(f.read(), format='PEM')
                self.modulus_var.set(str(self.public_key.n))
                self.public_exp_var.set(str(self.public_key.e))
                messagebox.showinfo("Success", "Public key loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load public key: {str(e)}")

    def open_private_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    self.private_key = rsa.PrivateKey.load_pkcs1(f.read(), format='PEM')
                self.modulus_var.set(str(self.private_key.n))
                self.private_exp_var.set(str(self.private_key.d))
                messagebox.showinfo("Success", "Private key loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load private key: {str(e)}")

    def select_input_file(self):
        file_path = filedialog.askopenfilename()
        self.input_file_var.set(file_path)

    def select_output_folder(self):
        folder_path = filedialog.askdirectory()
        self.output_file_var.set(folder_path)

    def encrypt_file(self):
        input_file = self.input_file_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Invalid input file")
            return

        try:
            with open(input_file, 'rb') as f:
                data = f.read()

            # Lấy tên file gốc
            original_filename = os.path.basename(input_file)

            # Tính toán kích thước tối đa của khối dựa trên module n của public_key
            max_chunk_size = (self.public_key.n.bit_length() // 8) - 11

            encrypted_chunks = []
            # Chia dữ liệu thành các khối nhỏ hơn và mã hóa từng khối
            for i in range(0, len(data), max_chunk_size):
                chunk = data[i:i + max_chunk_size]
                encrypted_chunk = rsa.encrypt(chunk, self.public_key)
                encrypted_chunks.append(encrypted_chunk)

            # Ghép các khối mã hóa lại với nhau
            encrypted_data = b''.join(encrypted_chunks)

            # Thêm tên file gốc vào dữ liệu mã hóa
            encrypted_data_with_filename = original_filename.encode() + b'\0' + encrypted_data

            # Ghi dữ liệu mã hóa ra file
            output_file = os.path.join(self.output_file_var.get(), "encrypted_file")
            with open(output_file, 'wb') as f:
                f.write(encrypted_data_with_filename)

            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        input_file = self.input_file_var.get()
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Invalid input file")
            return

        try:
            with open(input_file, 'rb') as f:
                encrypted_data_with_filename = f.read()

            # Tách tên file gốc và dữ liệu mã hóa
            original_filename, encrypted_data = encrypted_data_with_filename.split(b'\0', 1)

            # Tính toán kích thước tối đa của khối giải mã dựa trên module n của private_key
            max_chunk_size = (self.private_key.n.bit_length() // 8)

            decrypted_chunks = []
            # Chia dữ liệu thành các khối và giải mã từng khối
            for i in range(0, len(encrypted_data), max_chunk_size):
                chunk = encrypted_data[i:i + max_chunk_size]
                decrypted_chunk = rsa.decrypt(chunk, self.private_key)
                decrypted_chunks.append(decrypted_chunk)

            # Ghép các khối giải mã lại với nhau
            decrypted_data = b''.join(decrypted_chunks)

            # Sử dụng tên file gốc để lưu file giải mã
            output_file = os.path.join(self.output_file_var.get(), original_filename.decode())
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as {output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

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
