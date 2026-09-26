# BÀI TẬP: AN TOÀN VÀ BẢO MẬT THÔNG TIN

## Câu 1: Thuật toán mã hoá DES và AES

### 1.1. Tìm hiểu thuật toán mã hoá hiện đại DES, AES

**a) DES (Data Encryption Standard)**

- Kích thước khối dữ liệu: 64 bit
- Kích thước khoá: 56 bit hiệu dụng (lưu trữ dưới dạng 64 bit, trong đó có 8 bit dùng để kiểm tra chẵn lẻ - parity)
- Cấu trúc: mạng Feistel (Feistel network), gồm 16 vòng lặp
- Nguyên lý mỗi vòng:
  - Chia khối 64 bit thành 2 nửa L (trái) và R (phải), mỗi nửa 32 bit
  - Nửa phải R đi qua hàm F gồm: mở rộng (Expansion) từ 32 lên 48 bit → XOR với khoá con 48 bit của vòng đó → thay thế qua các hộp S-box (rút gọn về 32 bit) → hoán vị (Permutation)
  - Kết quả hàm F được XOR với nửa trái L, sau đó hai nửa hoán đổi vị trí cho nhau
- Sinh khoá con: khoá gốc 64 bit qua hoán vị PC-1 (loại bỏ bit parity, còn 56 bit), chia đôi, mỗi vòng dịch trái (rotate) 1 hoặc 2 bit tuỳ vòng, sau đó qua hoán vị PC-2 để tạo khoá con 48 bit cho vòng đó
- Nhược điểm: không gian khoá 56 bit quá nhỏ so với năng lực tính toán hiện nay, dễ bị tấn công vét cạn (brute-force) → hiện không còn được khuyến nghị dùng, đã bị AES thay thế

**b) AES (Advanced Encryption Standard)**

- Kích thước khối dữ liệu: cố định 128 bit
- Kích thước khoá: 128 / 192 / 256 bit, tương ứng số vòng lặp là 10 / 12 / 14 vòng
- Cấu trúc: mạng thay thế - hoán vị (SPN - Substitution Permutation Network), khác với Feistel của DES
- Dữ liệu được biểu diễn dưới dạng ma trận trạng thái (state) 4×4 byte
- Mỗi vòng (trừ vòng cuối) gồm 4 phép biến đổi:
  1. **SubBytes**: thay thế từng byte của state bằng giá trị tương ứng trong bảng S-box (S-box được xây dựng từ phép nghịch đảo trong trường hữu hạn GF(2⁸) kết hợp một biến đổi affine)
  2. **ShiftRows**: dịch vòng trái các hàng của ma trận state - hàng 0 giữ nguyên, hàng 1 dịch 1 byte, hàng 2 dịch 2 byte, hàng 3 dịch 3 byte
  3. **MixColumns**: trộn 4 byte trong từng cột bằng phép nhân ma trận cố định trong GF(2⁸) - bước này bị bỏ qua ở vòng cuối cùng
  4. **AddRoundKey**: XOR state với khoá con (round key) của vòng hiện tại
- Sinh khoá con: dùng thuật toán Key Expansion, sử dụng các hàm RotWord (xoay từ), SubWord (thay thế qua S-box) và hằng số vòng Rcon, sinh ra tổng cộng (số vòng + 1) khoá con
- Ưu điểm so với DES: không gian khoá lớn hơn nhiều, cấu trúc toán học chặt chẽ, tốc độ xử lý nhanh, hiện là chuẩn mã hoá được dùng phổ biến nhất thế giới (chuẩn hoá bởi NIST năm 2001)

### 1.2. Quy trình mã hoá / giải mã AES

**Mã hoá:**
```
AddRoundKey (dùng khoá con 0)
Lặp (Nr - 1) vòng:
    SubBytes → ShiftRows → MixColumns → AddRoundKey
Vòng cuối cùng (không có MixColumns):
    SubBytes → ShiftRows → AddRoundKey
```

**Giải mã** (thực hiện ngược lại, dùng các phép biến đổi nghịch và khoá con theo thứ tự đảo ngược):
```
AddRoundKey (dùng khoá con cuối cùng)
Lặp (Nr - 1) vòng:
    InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
Vòng cuối cùng:
    InvShiftRows → InvSubBytes → AddRoundKey
```

> **[CHÈN ẢNH: sơ đồ khối minh hoạ quy trình mã hoá/giải mã AES qua các vòng — có thể tự vẽ bằng draw.io hoặc PowerPoint, hoặc tìm ảnh sơ đồ AES trên mạng]**

### 1.3. Cài đặt AES trên ngôn ngữ lập trình Python

Chương trình cài đặt AES-128 hoàn chỉnh từ đầu (không dùng thư viện mã hoá), gồm đầy đủ các thành phần: bảng S-box, phép toán trong trường GF(2⁸), thuật toán sinh khoá con (Key Expansion), 4 phép biến đổi SubBytes/ShiftRows/MixColumns/AddRoundKey và các phép nghịch đảo tương ứng khi giải mã.

Chương trình đã được kiểm chứng bằng cách đối chiếu kết quả với thư viện chuẩn `pycryptodome`, dùng cùng vector kiểm tra chuẩn FIPS-197 của NIST — kết quả trùng khớp tuyệt đối ở cả bước mã hoá và giải mã.

**Kết quả chạy chương trình:**
```
=== 1) Kiểm tra với vector chuẩn FIPS-197 (1 khối 16 byte) ===
Khoá        : 000102030405060708090a0b0c0d0e0f
Bản rõ      : 00112233445566778899aabbccddeeff
Mã hoá (tự viết)     : 69c4e0d86a7b0430d8cdb78070b4c55a
Mã hoá (pycryptodome): 69c4e0d86a7b0430d8cdb78070b4c55a
=> Trùng khớp: True
Giải mã (tự viết) khớp bản rõ gốc: True

=== 2) Mã hoá 1 đoạn văn bản dài (nhiều khối, chế độ ECB + PKCS7) ===
Thông điệp gốc: b'Mon An toan va bao mat thong tin - demo AES tu cai dat'
Bản mã (tự viết)      : 9be170e4dbd8663dff7f3f0b5f479f24657d7cb4ffb93c42e3569ba2314598e...
Bản mã (pycryptodome) : 9be170e4dbd8663dff7f3f0b5f479f24657d7cb4ffb93c42e3569ba2314598e...
=> Trùng khớp: True
Giải mã lại (tự viết) : Mon An toan va bao mat thong tin - demo AES tu cai dat
=> Khớp thông điệp gốc: True
```

> **[CHÈN ẢNH: screenshot cửa sổ VS Code terminal khi chạy `python aes_demo.py` — bạn đã có sẵn ảnh này từ lúc chạy thử]**

Toàn bộ mã nguồn được đính kèm trong file `aes_demo.py` nộp cùng bài này.

---

## Câu 2: Thuật toán mã hoá bất đối xứng RSA

### 2.1. Nguyên lý chung

RSA (Rivest–Shamir–Adleman) là thuật toán mã hoá khoá công khai (bất đối xứng) đầu tiên được ứng dụng rộng rãi, dựa trên độ khó của bài toán **phân tích một số nguyên rất lớn thành thừa số nguyên tố**. Với các số nguyên tố đủ lớn (hàng nghìn bit), việc phân tích ngược là bất khả thi về mặt tính toán trong thời gian hợp lý.

RSA sử dụng một cặp khoá:

- **Khoá công khai (public key)**: dùng để mã hoá, công bố rộng rãi cho mọi người
- **Khoá bí mật (private key)**: dùng để giải mã, chỉ chủ sở hữu giữ, không được tiết lộ

### 2.2. Quy trình sinh cặp khoá bí mật / công khai

1. Chọn ngẫu nhiên hai số nguyên tố lớn, khác nhau: **p** và **q**
2. Tính **n = p × q** (n gọi là modulus, xuất hiện trong cả 2 khoá)
3. Tính giá trị hàm Euler: **φ(n) = (p − 1)(q − 1)**
4. Chọn số **e** sao cho: 1 < e < φ(n) và gcd(e, φ(n)) = 1 (e nguyên tố cùng nhau với φ(n)); trong thực tế thường chọn **e = 65537**
5. Tính **d** là nghịch đảo modulo của e theo φ(n), tức là số d thoả: **d × e ≡ 1 (mod φ(n))** — tính bằng thuật toán Euclid mở rộng
6. Kết quả:
   - **Khoá công khai: (n, e)**
   - **Khoá bí mật: (n, d)**

**Mã hoá:** C = Mᵉ mod n
**Giải mã:** M = Cᵈ mod n (trong đó M là bản rõ, C là bản mã)

### 2.3. Ví dụ minh hoạ với số nhỏ (để dễ hiểu nguyên lý)

- Chọn p = 61, q = 53 → n = p × q = 3233
- φ(n) = (61−1)(53−1) = 60 × 52 = 3120
- Chọn e = 17 (thoả gcd(17, 3120) = 1)
- Tính d sao cho 17 × d ≡ 1 (mod 3120) → d = 2753
- Khoá công khai: (n=3233, e=17); Khoá bí mật: (n=3233, d=2753)
- Mã hoá bản rõ M = 65: C = 65¹⁷ mod 3233 = 2790
- Giải mã: M = 2790²⁷⁵³ mod 3233 = 65 (khớp lại bản rõ ban đầu)

> **[CHÈN ẢNH: nếu viết thêm đoạn code Python dùng thư viện `rsa` hoặc `cryptography` để sinh khoá và mã hoá/giải mã thật, chèn ảnh kết quả chạy vào đây]**

### 2.4. Vì sao RSA an toàn

Độ an toàn của RSA nằm ở việc: biết n rất khó (trên thực tế là không khả thi với công nghệ hiện tại) để tìm ra p và q nếu chúng đủ lớn (RSA hiện dùng phổ biến với n có độ dài 2048 hoặc 3072 bit). Nếu không biết p, q thì không thể tính được φ(n), do đó không thể suy ra khoá bí mật d từ khoá công khai (n, e).

---

## Câu 3: Mô hình xác thực dùng RSA và so sánh với AES

### 3.1. Các mô hình xác thực sử dụng RSA

**a) Xác thực người gửi (Sender Authentication - chữ ký số)**

- Người gửi tính giá trị băm (hash) của thông điệp, sau đó **mã hoá bằng khoá bí mật của chính mình** → tạo ra "chữ ký số" đính kèm thông điệp
- Người nhận dùng **khoá công khai của người gửi** để giải mã chữ ký, thu được giá trị hash; đồng thời tự tính hash của thông điệp nhận được rồi so sánh hai giá trị
- Nếu trùng khớp → xác nhận thông điệp đúng là do người gửi đó tạo ra, không bị giả mạo hay sửa đổi trên đường truyền
- Đây chính là nguyên lý của **chữ ký số (digital signature)**

**b) Xác thực người nhận (đảm bảo tính bí mật - Confidentiality)**

- Người gửi **mã hoá thông điệp bằng khoá công khai của người nhận**
- Chỉ người nhận có khoá bí mật tương ứng mới giải mã được nội dung
- Đảm bảo chỉ đúng người nhận dự kiến mới đọc được thông điệp, người khác chặn được bản mã cũng không giải mã nổi

**c) Kết hợp cả hai mô hình (vừa xác thực người gửi, vừa xác thực người nhận)**

- Bước 1: Người gửi ký thông điệp bằng khoá bí mật của mình (đảm bảo xác thực nguồn gốc)
- Bước 2: Kết quả sau khi ký tiếp tục được mã hoá bằng khoá công khai của người nhận (đảm bảo bí mật)
- Người nhận thực hiện ngược lại: giải mã bằng khoá bí mật của mình trước, sau đó xác minh chữ ký bằng khoá công khai của người gửi
- Mô hình này đạt được đồng thời cả 2 mục tiêu: **tính bí mật (confidentiality)** và **tính xác thực, chống chối bỏ (authentication, non-repudiation)**

> **[CHÈN ẢNH: vẽ sơ đồ minh hoạ luồng dữ liệu của mô hình (c) — người gửi → ký bằng khoá bí mật gửi → mã hoá bằng khoá công khai nhận → gửi đi → người nhận giải mã bằng khoá bí mật nhận → xác minh bằng khoá công khai gửi]**

### 3.2. So sánh thời gian mã hoá / giải mã giữa RSA và AES

| Tiêu chí | AES (đối xứng) | RSA (bất đối xứng) |
|---|---|---|
| Tốc độ mã hoá/giải mã | Rất nhanh (hàng trăm MB/s) | Chậm hơn nhiều (thường chậm hơn 100–1000 lần so với AES) |
| Cơ chế xử lý | Các phép toán trên byte đơn giản (thay thế, hoán vị, XOR) | Phép luỹ thừa modulo với số rất lớn, tốn nhiều phép tính |
| Độ dài khoá điển hình | 128 / 192 / 256 bit | 2048 / 3072 bit trở lên (dài hơn nhiều mới đạt độ an toàn tương đương) |
| Mã hoá dữ liệu lớn | Phù hợp | Không phù hợp (quá chậm, giới hạn kích thước bản rõ theo n) |
| Quản lý và trao đổi khoá | Phức tạp hơn (2 bên phải cùng biết trước 1 khoá bí mật chung) | Đơn giản hơn (chỉ cần công bố khoá công khai) |

Ghi chú: thời gian giải mã của RSA (dùng số mũ d lớn) thường **chậm hơn** thời gian mã hoá (dùng số mũ e nhỏ như 65537).

> **[CHÈN ẢNH: nếu viết code đo thời gian thực tế bằng `time.perf_counter()` khi mã hoá/giải mã cùng 1 dữ liệu bằng cả AES và RSA, chèn biểu đồ/số liệu đo được vào đây để minh hoạ trực quan hơn]**

### 3.3. Kết hợp sức mạnh của RSA và AES — Mã hoá lai (Hybrid Encryption)

Vì AES nhanh nhưng khó trao đổi khoá bí mật an toàn qua mạng công cộng, còn RSA trao đổi khoá dễ dàng nhưng lại quá chậm để mã hoá dữ liệu lớn, thực tế người ta kết hợp cả hai:

1. Sinh ngẫu nhiên một **khoá phiên (session key)** dùng cho AES
2. Dùng **AES** với khoá phiên đó để mã hoá toàn bộ dữ liệu thực sự cần truyền (nhanh, phù hợp dữ liệu lớn)
3. Dùng **RSA** với khoá công khai của người nhận để mã hoá riêng khoá phiên AES (khoá này rất ngắn nên RSA xử lý nhanh, không đáng kể)
4. Gửi đi cả bản mã dữ liệu (bằng AES) và khoá phiên đã mã hoá (bằng RSA)
5. Người nhận dùng khoá bí mật RSA của mình giải mã ra khoá phiên, sau đó dùng khoá phiên đó để giải mã dữ liệu bằng AES

Đây chính là mô hình được áp dụng thực tế trong các giao thức bảo mật phổ biến hiện nay như **TLS/SSL** (bảo mật web HTTPS), **PGP** (mã hoá email), giúp tận dụng đồng thời: tốc độ xử lý nhanh của AES và khả năng trao đổi khoá an toàn, tiện lợi của RSA.

---

*(Hết bài làm)*
