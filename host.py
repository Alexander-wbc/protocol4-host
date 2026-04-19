import socket
import threading
import time
import json
import zlib
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


class ErrorInjector:
    def __init__(self):
        self.mode = "normal"
        self.used = False
        self.lock = threading.Lock()

    def set_mode(self, mode: str):
        with self.lock:
            self.mode = mode
            self.used = False

    def should_apply(self, packet_type: str) -> bool:
        with self.lock:
            if self.used:
                return False

            mode_map = {
                "drop_first_data": "DATA",
                "drop_first_ack": "ACK",
                "corrupt_first_data": "DATA",
                "corrupt_first_ack": "ACK",
            }

            if self.mode in mode_map and mode_map[self.mode] == packet_type:
                self.used = True
                return True
            return False

    def get_mode(self):
        with self.lock:
            return self.mode


class Protocol4Node:
    def __init__(self, name, local_addr, peer_addr, ui_queue, injector, timeout=2.0):
        self.name = name
        self.local_addr = local_addr
        self.peer_addr = peer_addr
        self.ui_queue = ui_queue
        self.injector = injector
        self.timeout = timeout

        self.sock = None
        self.running = False

        self.send_seq = 0
        self.expected_seq = 0
        self.waiting_ack = False

        self.last_frame_bytes = None
        self.last_frame_seq = None
        self.last_payload = ""
        self.last_send_time = 0.0

        self.send_lock = threading.Lock()

    def post_ui(self, kind, data):
        self.ui_queue.put((kind, data))

    def log(self, msg):
        now = time.strftime("%H:%M:%S")
        self.post_ui("log", f"[{now}] [{self.name}] {msg}")

    def report_state(self):
        self.post_ui(
            "state",
            {
                "node": self.name,
                "send_seq": self.send_seq,
                "expected_seq": self.expected_seq,
                "waiting_ack": self.waiting_ack,
            },
        )

    @staticmethod
    def compute_crc(body):
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return zlib.crc32(raw) & 0xFFFFFFFF

    def build_packet(self, pkt_type, seq, payload=""):
        body = {
            "type": pkt_type,
            "seq": int(seq),
            "payload": payload,
        }
        pkt = dict(body)
        pkt["checksum"] = self.compute_crc(body)
        return json.dumps(pkt, separators=(",", ":")).encode("utf-8")

    def corrupt_packet_bytes(self, packet_bytes):
        pkt = json.loads(packet_bytes.decode("utf-8"))
        pkt["checksum"] = (pkt["checksum"] + 1) & 0xFFFFFFFF
        return json.dumps(pkt, separators=(",", ":")).encode("utf-8")

    def parse_packet(self, packet_bytes):
        try:
            pkt = json.loads(packet_bytes.decode("utf-8"))
            if not all(k in pkt for k in ("type", "seq", "payload", "checksum")):
                return None
            if pkt["type"] not in ("DATA", "ACK"):
                return None
            if pkt["seq"] not in (0, 1):
                return None

            body = {
                "type": pkt["type"],
                "seq": pkt["seq"],
                "payload": pkt["payload"],
            }
            if self.compute_crc(body) != pkt["checksum"]:
                return None
            return pkt
        except Exception:
            return None

    def start(self):
        if self.running:
            return

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.local_addr)
        self.sock.settimeout(0.3)
        self.running = True

        threading.Thread(target=self.recv_loop, daemon=True).start()
        threading.Thread(target=self.timer_loop, daemon=True).start()

        self.log(f"节点启动，本地 {self.local_addr}，对端 {self.peer_addr}")
        self.report_state()

    def stop(self):
        if not self.running:
            return
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.log("节点停止")
        self.report_state()

    def maybe_inject(self, pkt_type, packet_bytes):
        mode = self.injector.get_mode()

        if mode == "normal":
            return "send", packet_bytes, ""

        if not self.injector.should_apply(pkt_type):
            return "send", packet_bytes, ""

        if mode == "drop_first_data" and pkt_type == "DATA":
            return "drop", None, "[错误注入] 首次 DATA 被丢弃"
        if mode == "drop_first_ack" and pkt_type == "ACK":
            return "drop", None, "[错误注入] 首次 ACK 被丢弃"
        if mode == "corrupt_first_data" and pkt_type == "DATA":
            return "corrupt", self.corrupt_packet_bytes(packet_bytes), "[错误注入] 首次 DATA 被损坏"
        if mode == "corrupt_first_ack" and pkt_type == "ACK":
            return "corrupt", self.corrupt_packet_bytes(packet_bytes), "[错误注入] 首次 ACK 被损坏"

        return "send", packet_bytes, ""

    def send_raw(self, pkt_bytes):
        self.sock.sendto(pkt_bytes, self.peer_addr)

    def send_ack(self, seq):
        pkt = self.build_packet("ACK", seq, "")
        action, out_pkt, note = self.maybe_inject("ACK", pkt)

        if note:
            self.log(note)

        if action == "drop":
            return

        self.send_raw(out_pkt)
        self.log(f"--> 发送 ACK(seq={seq})")

    def send_message(self, msg):
        if not self.running:
            return False, "系统未启动"

        with self.send_lock:
            if self.waiting_ack:
                return False, "当前仍在等待 ACK，不能发送新数据"

            seq = self.send_seq
            self.last_frame_seq = seq
            self.last_payload = msg
            self.last_frame_bytes = self.build_packet("DATA", seq, msg)
            self.last_send_time = time.time()
            self.waiting_ack = True

            action, out_pkt, note = self.maybe_inject("DATA", self.last_frame_bytes)

            if note:
                self.log(note)

            if action == "drop":
                self.log(f"--> 发送 DATA(seq={seq}, payload={msg!r}) [已被注入丢弃]")
                self.report_state()
                return True, "已发送"

            self.send_raw(out_pkt)
            self.log(f"--> 发送 DATA(seq={seq}, payload={msg!r})")
            self.report_state()
            return True, "发送成功"

    def recv_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                if addr != self.peer_addr:
                    continue

                pkt = self.parse_packet(data)
                if pkt is None:
                    self.log("[校验失败] 收到损坏帧/非法帧，已丢弃")
                    continue

                if pkt["type"] == "DATA":
                    self.handle_data(pkt)
                else:
                    self.handle_ack(pkt)

            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                self.log(f"[异常] 接收错误: {e}")
                break

    def handle_data(self, pkt):
        seq = pkt["seq"]
        payload = pkt["payload"]

        self.log(f"<-- 收到 DATA(seq={seq}, payload={payload!r})")

        if seq == self.expected_seq:
            self.log(f"[交付上层] {payload}")
            self.send_ack(seq)
            self.expected_seq ^= 1
            self.log(f"[接收状态] expected_seq 切换为 {self.expected_seq}")
        else:
            self.log(f"[重复帧] DATA(seq={seq}) 为重复帧，不重复交付，仅重发 ACK")
            self.send_ack(seq)

        self.report_state()

    def handle_ack(self, pkt):
        seq = pkt["seq"]
        self.log(f"<-- 收到 ACK(seq={seq})")

        with self.send_lock:
            if self.waiting_ack and seq == self.last_frame_seq:
                self.waiting_ack = False
                self.send_seq ^= 1
                self.log(f"[发送完成] send_seq 切换为 {self.send_seq}")
            else:
                self.log("[忽略] 该 ACK 不是当前等待的 ACK")

        self.report_state()

    def timer_loop(self):
        while self.running:
            time.sleep(0.05)

            with self.send_lock:
                if self.waiting_ack and self.last_frame_bytes is not None:
                    if time.time() - self.last_send_time >= self.timeout:
                        self.last_send_time = time.time()
                        self.log(
                            f"[超时] DATA(seq={self.last_frame_seq}) 在 {self.timeout:.2f}s 内未获确认，准备重传"
                        )

                        action, out_pkt, note = self.maybe_inject("DATA", self.last_frame_bytes)

                        if note:
                            self.log(note)

                        if action == "drop":
                            self.log(f"--> 重传 DATA(seq={self.last_frame_seq}) [已被注入丢弃]")
                            self.report_state()
                            continue

                        self.send_raw(out_pkt)
                        self.log(f"--> 重传 DATA(seq={self.last_frame_seq}, payload={self.last_payload!r})")
                        self.report_state()


class Protocol4SimpleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Protocol 4 单窗口 UDP 演示平台")
        self.root.geometry("1080x700")
        self.root.minsize(980, 620)

        self.ui_queue = queue.Queue()
        self.injector = ErrorInjector()

        self.node_a = None
        self.node_b = None
        self.running = False

        self.build_vars()
        self.build_ui()

        self.root.after(100, self.process_ui_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_vars(self):
        self.timeout_var = tk.StringVar(value="2.0")
        self.mode_var = tk.StringVar(value="normal")

        self.a_send_seq_var = tk.StringVar(value="0")
        self.a_expected_seq_var = tk.StringVar(value="0")

        self.b_send_seq_var = tk.StringVar(value="0")
        self.b_expected_seq_var = tk.StringVar(value="0")

    def build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        ctrl = ttk.LabelFrame(self.root, text="控制区")
        ctrl.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
        for i in range(8):
            ctrl.columnconfigure(i, weight=1)

        ttk.Label(ctrl, text="UDP地址").grid(row=0, column=0, padx=5, pady=6, sticky="e")
        ttk.Label(ctrl, text="A: 127.0.0.1:9000    B: 127.0.0.1:9001").grid(
            row=0, column=1, columnspan=2, padx=5, pady=6, sticky="w"
        )

        ttk.Label(ctrl, text="超时(s)").grid(row=0, column=3, padx=5, pady=6, sticky="e")
        ttk.Entry(ctrl, textvariable=self.timeout_var, width=10).grid(
            row=0, column=4, padx=5, pady=6, sticky="ew"
        )

        ttk.Label(ctrl, text="错误模式").grid(row=0, column=5, padx=5, pady=6, sticky="e")
        ttk.Combobox(
            ctrl,
            textvariable=self.mode_var,
            state="readonly",
            values=[
                "normal",
                "drop_first_data",
                "drop_first_ack",
                "corrupt_first_data",
                "corrupt_first_ack",
            ],
        ).grid(row=0, column=6, padx=5, pady=6, sticky="ew")

        btn_frame = ttk.Frame(ctrl)
        btn_frame.grid(row=0, column=7, padx=5, pady=6, sticky="ew")
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        self.start_btn = ttk.Button(btn_frame, text="启动", command=self.start_system)
        self.start_btn.grid(row=0, column=0, padx=2, sticky="ew")

        self.stop_btn = ttk.Button(btn_frame, text="停止", command=self.stop_system, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=2, sticky="ew")

        send_frame = ttk.LabelFrame(self.root, text="发送区")
        send_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        send_frame.columnconfigure(1, weight=1)
        send_frame.columnconfigure(4, weight=1)

        ttk.Label(send_frame, text="A → B").grid(row=0, column=0, padx=5, pady=6)
        self.a_input = ttk.Entry(send_frame)
        self.a_input.grid(row=0, column=1, padx=5, pady=6, sticky="ew")
        ttk.Button(send_frame, text="发送 A→B", command=self.send_a_to_b).grid(row=0, column=2, padx=5, pady=6)

        ttk.Label(send_frame, text="B → A").grid(row=0, column=3, padx=5, pady=6)
        self.b_input = ttk.Entry(send_frame)
        self.b_input.grid(row=0, column=4, padx=5, pady=6, sticky="ew")
        ttk.Button(send_frame, text="发送 B→A", command=self.send_b_to_a).grid(row=0, column=5, padx=5, pady=6)

        ttk.Button(send_frame, text="重置错误模式", command=self.reset_injector).grid(row=0, column=6, padx=5, pady=6)
        ttk.Button(send_frame, text="清空日志", command=self.clear_log).grid(row=0, column=7, padx=5, pady=6)

        main = ttk.Frame(self.root)
        main.grid(row=2, column=0, sticky="nsew", padx=10, pady=8)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(1, weight=1)

        a_state = ttk.LabelFrame(main, text="节点 A 核心状态")
        a_state.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 8))
        self.build_state_panel_a(a_state)

        b_state = ttk.LabelFrame(main, text="节点 B 核心状态")
        b_state.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 8))
        self.build_state_panel_b(b_state)

        log_frame = ttk.LabelFrame(main, text="总日志")
        log_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, state="disabled", font=("Consolas", 10)
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

    def build_state_panel_a(self, parent):
        for i in range(2):
            parent.columnconfigure(i, weight=1)

        ttk.Label(parent, text="send_seq").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ttk.Label(parent, textvariable=self.a_send_seq_var, relief="sunken").grid(
            row=0, column=1, sticky="ew", padx=8, pady=8
        )

        ttk.Label(parent, text="expected_seq").grid(row=1, column=0, sticky="w", padx=8, pady=8)
        ttk.Label(parent, textvariable=self.a_expected_seq_var, relief="sunken").grid(
            row=1, column=1, sticky="ew", padx=8, pady=8
        )

        ttk.Label(parent, text="ACK状态").grid(row=2, column=0, sticky="w", padx=8, pady=8)
        a_ack_frame = ttk.Frame(parent)
        a_ack_frame.grid(row=2, column=1, sticky="w", padx=8, pady=8)

        self.a_ack_canvas = tk.Canvas(a_ack_frame, width=22, height=22, highlightthickness=0)
        self.a_ack_canvas.pack(side="left")
        self.a_ack_light = self.a_ack_canvas.create_oval(3, 3, 19, 19, fill="green", outline="black")

        self.a_ack_label = ttk.Label(a_ack_frame, text="空闲")
        self.a_ack_label.pack(side="left", padx=6)

    def build_state_panel_b(self, parent):
        for i in range(2):
            parent.columnconfigure(i, weight=1)

        ttk.Label(parent, text="send_seq").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ttk.Label(parent, textvariable=self.b_send_seq_var, relief="sunken").grid(
            row=0, column=1, sticky="ew", padx=8, pady=8
        )

        ttk.Label(parent, text="expected_seq").grid(row=1, column=0, sticky="w", padx=8, pady=8)
        ttk.Label(parent, textvariable=self.b_expected_seq_var, relief="sunken").grid(
            row=1, column=1, sticky="ew", padx=8, pady=8
        )

        ttk.Label(parent, text="ACK状态").grid(row=2, column=0, sticky="w", padx=8, pady=8)
        b_ack_frame = ttk.Frame(parent)
        b_ack_frame.grid(row=2, column=1, sticky="w", padx=8, pady=8)

        self.b_ack_canvas = tk.Canvas(b_ack_frame, width=22, height=22, highlightthickness=0)
        self.b_ack_canvas.pack(side="left")
        self.b_ack_light = self.b_ack_canvas.create_oval(3, 3, 19, 19, fill="green", outline="black")

        self.b_ack_label = ttk.Label(b_ack_frame, text="空闲")
        self.b_ack_label.pack(side="left", padx=6)

    def set_ack_light(self, node, waiting_ack):
        color = "red" if waiting_ack else "green"
        text = "等待ACK" if waiting_ack else "空闲"

        if node == "A":
            self.a_ack_canvas.itemconfig(self.a_ack_light, fill=color)
            self.a_ack_label.config(text=text)
        else:
            self.b_ack_canvas.itemconfig(self.b_ack_light, fill=color)
            self.b_ack_label.config(text=text)

    def append_log(self, text):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def process_ui_queue(self):
        try:
            while True:
                kind, data = self.ui_queue.get_nowait()
                if kind == "log":
                    self.append_log(data)
                elif kind == "state":
                    self.update_state(data)
        except queue.Empty:
            pass
        self.root.after(100, self.process_ui_queue)

    def update_state(self, state):
        if state["node"] == "A":
            self.a_send_seq_var.set(str(state["send_seq"]))
            self.a_expected_seq_var.set(str(state["expected_seq"]))
            self.set_ack_light("A", state["waiting_ack"])
        else:
            self.b_send_seq_var.set(str(state["send_seq"]))
            self.b_expected_seq_var.set(str(state["expected_seq"]))
            self.set_ack_light("B", state["waiting_ack"])

    def start_system(self):
        if self.running:
            messagebox.showinfo("提示", "系统已经启动")
            return

        try:
            timeout = float(self.timeout_var.get().strip())
            if timeout <= 0:
                raise ValueError("超时时间必须大于 0")

            self.injector.set_mode(self.mode_var.get())

            self.node_a = Protocol4Node(
                "A",
                ("127.0.0.1", 9000),
                ("127.0.0.1", 9001),
                self.ui_queue,
                self.injector,
                timeout,
            )
            self.node_b = Protocol4Node(
                "B",
                ("127.0.0.1", 9001),
                ("127.0.0.1", 9000),
                self.ui_queue,
                self.injector,
                timeout,
            )

            self.node_a.start()
            self.node_b.start()
            self.running = True

            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.append_log(f"[系统] 当前错误模式: {self.mode_var.get()}")

        except Exception as e:
            self.node_a = None
            self.node_b = None
            self.running = False
            messagebox.showerror("启动失败", str(e))

    def stop_system(self):
        if self.node_a:
            self.node_a.stop()
        if self.node_b:
            self.node_b.stop()

        self.node_a = None
        self.node_b = None
        self.running = False

        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

        self.set_ack_light("A", False)
        self.set_ack_light("B", False)

    def reset_injector(self):
        self.injector.set_mode(self.mode_var.get())
        self.append_log(f"[系统] 已重置错误模式: {self.mode_var.get()}")

    def send_a_to_b(self):
        if not self.running or not self.node_a:
            messagebox.showwarning("提示", "请先启动系统")
            return

        msg = self.a_input.get().strip()
        if not msg:
            messagebox.showwarning("提示", "A→B 发送内容不能为空")
            return

        ok, info = self.node_a.send_message(msg)
        if not ok:
            messagebox.showwarning("发送失败", info)

    def send_b_to_a(self):
        if not self.running or not self.node_b:
            messagebox.showwarning("提示", "请先启动系统")
            return

        msg = self.b_input.get().strip()
        if not msg:
            messagebox.showwarning("提示", "B→A 发送内容不能为空")
            return

        ok, info = self.node_b.send_message(msg)
        if not ok:
            messagebox.showwarning("发送失败", info)

    def on_close(self):
        self.stop_system()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    Protocol4SimpleGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()