use std::{ffi::{c_void, CString}};

use nix::{
    sys::{
        wait::{waitpid, WaitStatus}, ptrace,
    },
    unistd::{execvp, fork, ForkResult, Pid}, libc::c_char,
};

use crate::helper::DynError;

/// デバッガ内の情報
pub struct DbgInfo {
    pid: Pid,
    brk_addr: Option<*mut c_void>,
    brk_val: i64,
    filename: String,
}

/// デバッガ
/// ZDbg<Running>は子プロセスを実行中
/// ZDbg<NotRunning>は子プロセスを実行していない
pub struct ZDbg<T> {
    info: Box<DbgInfo>,
    _state: T,
}

/// デバッガの状態
pub struct Running; // 実行している
pub struct NotRunning; // 実行していない

/// デバッガの状態の列挙型表現
/// Exitの場合終了
pub enum State {
    Running(ZDbg<Running>),
    NotRunning(ZDbg<NotRunning>),
    Exit,
}

/// RunningとNotRunningで共通の実装
impl<T> ZDbg<T> {
    /// ブレークポイントのアドレスを設定する関数
    /// 子プロセスのメモリ上には反映しない
    /// アドレス設定に成功した場合はtrueを返す
    fn set_break_addr(&mut self, cmd: &[&str]) -> bool {
        if self.info.brk_addr.is_some() {
            eprintln!(
                "<<ブレークポイントは設定済みです : Addr = {:p}>>",
                self.info.brk_addr.unwrap()
            );
            false
        } else if let Some(addr) = get_break_addr(cmd) {
            self.info.brk_addr = Some(addr);
            true
        } else {
            false
        }
    }

    ///
    fn get_break_addr(self, cmd: &[&str]) -> Option<*mut c_void> {}

    /// 共通のコマンドを実行
    fn do_cmd_common(&self, cmd: &[&str]) {
        match cmd[0] {
            "help" | "h" => do_help(),
            _ => (),
        }
    }
}

/// NotRunning時に呼び出し可能なメソッド
impl ZDbg<NotRunning> {
    pub fn new(filename: String) -> Self {
        ZDbg {
            info: Box::new(DbgInfo {
                pid: Pid::from_raw(0),
                brk_addr: None,
                brk_val: 0,
                filename,
            }),
            _state: NotRunning,
        }
    }

    pub fn do_cmd(self, cmd: &[&str]) -> Result<State, DynError> {
        if cmd.is_empty() {
            return Ok(State::NotRunning(self));
        }

        match cmd[0] {
            "run" | "r" => return self.do_run(cmd),
            "break" | "b" => self.do_break(cmd),
            "exit" => return Ok(State::Exit),
            "continue" | "c" | "stepi" | "s" | "registers" | "regs" => {
                eprintln!("<<ターゲットを実行していません｡ runで実行してください｡>>")
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::NotRunning(self))
    }

    /// 子プロセスを生成し､成功した場合はRunning状態に遷移
    fn do_run(mut self, cmd: &[&str]) -> Result<State, DynError> {
        // 子プロセスに渡すコマンドライン引数
        let args: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();

        match unsafe { fork()? } {
            ForkResult::Child => {
                // ASLRを無効に
                let p = personality::get().unwrap();
                personality::set(p | Persona::ADDR_NO_RANDOMIZE).unwrap();
                ptrace::traceme().unwrap();

                // exec
                execvp(&CString::new(self.info.filename.as_str()).unwrap(), &args).unwrap();
                unreachable!();
            }
            ForkResult::Parent { child } => match waitpid(child, None)? {
                WaitStatus::Stopped(..) => {
                    println!("<<子プロセスの実行に成功しました : PID = {child}>>");
                    self.info.pid = child;
                    let mut dbg = ZDbg::<Running> {
                        info: self.info,
                        _state: Running,
                    };
                    dbg.set_break(); // ブレークポイントを設定
                    dbg.do_continue()
                }
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    Err("子プロセスの実行に失敗しました".into())
                }
                _ => Err("子プロセスが不正な状態です".into()),
            },
        }
    }
}

/// Running時に呼び出し可能なメソッド
impl ZDbg<Running> {
    fn do_cmd(self, cmd: &[&str]) -> Result<State, DynError> {
        if cmd.is_empty() {
            return Ok(State::Running(self));
        }

        match cmd[0] {
            "break" | "b" => self.do_break(cmd)?,
            "continue" | "c" => return self.do_continue(),
            "registers" | "regs" => {
                let args = ptrace::getregs(self.info.pid)?;
                print_regs(&args);
            }
            "stepi" | "s" => return self.do_stepi(),
            "run" | "r" => eprintln!("<<すでに実行中です>>"),
            "exit" => {
                self.do_exit()?;
                return Ok(State::Exit);
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::Running(self))
    }

    fn do_break(self, cmd: &[&str]) -> Result<(), DynError> {
        if self.set_break_addr(cmd) {
            self.set_break()>?;
        }
        Ok(())
    }

    /// continueを実行
    fn do_continue(self) -> Result<State, DynError> {
        // ブレークポイントで停止していた場合は1ステップ実行後再設定
        match self.step_and_break()? {
            State::Running(r) => {
                // 実行再開
                ptrace::cont(r.info.pid, None);
                r.wait_child()
            }
            n => Ok(n)
        }
    }

    fn do_stepi(self) -> Result<State, DynError> {}

    fn do_exit(self) -> Result<(), DynError> {
        loop {
            ptrace::kill(self.info.pid)?;
            match waitpid(self.info.pid, None)? {
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => return Ok(()),
                _ => (),
            }
        }
    }

    /// ブレークポイントを実際に設定
    /// つまり､該当アドレスのメモリを"int 3" = 0xccに設定
    fn set_break(&mut self) -> Result<(), DynError> {
        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(());
        };

        // ブレークするアドレスにあるメモリ上の値を取得
        let val = match ptrace::read(self.info.pid, addr as *mut c_char) {
            Ok(val) => val,
            Err(e) => {
                eprintln!("<<ptrace::readに失敗 : {e}, addr = {:p}>>", addr);
                return Ok(());
            }
        };

        // メモリ上の値を表示する補助関数
        fn print_val(addr: usize, val: i64) {
            print!("{:x}:", addr);
            for n in (0..8).map(|n| ((val >> (n * 8)) & 0xff) as u8) {
                print!(" {:x}", n);
            }
        }

        println!("<<以下のようにメモリを書き換えます>>");
        print!("<<before: "); // 元の値を表示
        print_val(addr as usize, val.into());
        println!(">>");

        let val_int3 = (val & !0xff) | 0xcc; // "int 3"に設定
        print!("<<after: "); // 変更後の値を表示
        print_val(addr as usize, val.into());
        println!(">>");

        // "int 3"をメモリに書き込み
        match unsafe {
            ptrace::write(self.info.pid, addr as *mut c_char, val_int3)
        } {
            Ok(_)   => {
                self.info.brk_addr = Some(addr);
                self.info.brk_val = val as i64; // 元の値を保存
            }
            Err(e) => {
                eprintln!("<<ptrace::writeに失敗 : {e}, addr = {:p}>>", addr);
            }
        }

        Ok(())
    }

    /// ブレークポイントで停止していた場合は
    /// 1ステップ実行しブレークポイントを再設定
    fn step_and_break(mut self) -> Result<State, DynError> {
        let regs = getregs(self.info.pid)?;
        if Some((regs.rip) as *mut c_void) == self.info.brk_addr {
            ptrace::step(self.info.pid, None)?; // 1ステップ実行
            match waitpid(self.info.pid, None)? {
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    println!("<<子プロセスが終了>>");
                    return Ok(State::NotRunning(ZDbg::<NotRunning> {info: self.info, _state: NotRunning}));
                }
                _=>(),
            }
            self.set_break()?;
        }

        Ok(State::Running(self))
    }
}
