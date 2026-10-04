use ilhook::x64::*;

pub trait AttachHandler = FnMut(&mut JmpContext) + 'static;
pub trait ReplaceHandler = FnMut(&mut RetContext) -> usize + 'static;

pub trait Patch {
    fn install(&self, session: &mut Session);
}

#[derive(Debug)]
pub enum HookError {
    AttachFailed(HookTarget),
    ReplaceFailed(HookTarget),
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookError::AttachFailed(t) => write!(f, "attach failed @ {t}"),
            HookError::ReplaceFailed(t) => write!(f, "replace failed @ {t}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HookTarget(usize);

impl HookTarget {
    pub fn from_addr(addr: usize) -> Self {
        Self(addr)
    }

    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize)
    }

    pub fn from_rva(base: usize, offset: usize) -> Self {
        Self(base + offset)
    }

    pub fn addr(self) -> usize {
        self.0
    }
}

impl std::fmt::Display for HookTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

pub struct JmpContext {
    regs: *mut Registers,
}

pub struct RetContext {
    pub trampoline: usize,
    regs: *mut Registers,
}

impl JmpContext {
    #[inline]
    pub fn regs(&mut self) -> &mut Registers {
        unsafe { &mut *self.regs }
    }
}

impl RetContext {
    #[inline]
    pub fn regs(&mut self) -> &mut Registers {
        unsafe { &mut *self.regs }
    }
}

#[derive(Default)]
pub struct HookEngine {
    hooks: Vec<HookPoint> = Vec::new(),
}

impl HookEngine {
    pub fn new() -> Self {
        Self { .. }
    }

    pub fn attach(
        &mut self,
        target: HookTarget,
        handler: impl AttachHandler,
    ) -> Result<(), HookError> {
        // double-box to get a stable fat pointer we can cast to usize
        let raw = Box::into_raw(Box::new(
            Box::new(handler) as Box<dyn FnMut(&mut JmpContext)>
        )) as usize;

        let h = Hooker::new(
            target.addr(),
            HookType::JmpBack(jmp_thunk),
            CallbackOption::None,
            raw,
            HookFlags::empty(),
        );

        unsafe {
            h.hook()
                .map(|point| self.hooks.push(point))
                .map_err(|_| HookError::AttachFailed(target))
        }
    }

    pub fn replace(
        &mut self,
        target: HookTarget,
        handler: impl ReplaceHandler,
    ) -> Result<(), HookError> {
        let raw = Box::into_raw(Box::new(
            Box::new(handler) as Box<dyn FnMut(&mut RetContext) -> usize>
        )) as usize;

        let h = Hooker::new(
            target.addr(),
            HookType::Retn(ret_thunk),
            CallbackOption::None,
            raw,
            HookFlags::empty(),
        );

        unsafe {
            h.hook()
                .map(|point| self.hooks.push(point))
                .map_err(|_| HookError::ReplaceFailed(target))
        }
    }

    pub fn persist(self) {
        std::mem::forget(self.hooks);
    }
}

pub struct Session {
    engine: HookEngine,
    tag: &'static str,
}

impl Session {
    pub fn new(tag: &'static str) -> Self {
        Self {
            engine: HookEngine::new(),
            tag,
        }
    }

    pub fn attach(&mut self, target: HookTarget, handler: impl AttachHandler) -> &mut Self {
        if let Err(e) = self.engine.attach(target, handler) {
            eprintln!("[{}] {e}", self.tag);
        }
        self
    }

    pub fn replace(&mut self, target: HookTarget, handler: impl ReplaceHandler) -> &mut Self {
        if let Err(e) = self.engine.replace(target, handler) {
            eprintln!("[{}] {e}", self.tag);
        }
        self
    }

    pub fn install(&mut self, patch: impl Patch) -> &mut Self {
        patch.install(self);
        self
    }

    pub fn install_all(&mut self, patches: &[&dyn Patch]) -> &mut Self {
        patches.iter().for_each(|p| p.install(self));
        self
    }

    pub fn persist(self) {
        eprintln!(
            "[{}] session persisted ({} hooks)",
            self.tag,
            self.engine.hooks.len()
        );
        self.engine.persist();
    }
}

unsafe extern "win64" fn jmp_thunk(regs: *mut Registers, handler: usize) {
    let f = unsafe { &mut *(handler as *mut Box<dyn FnMut(&mut JmpContext)>) };
    f(&mut JmpContext { regs });
}

unsafe extern "win64" fn ret_thunk(
    regs: *mut Registers,
    trampoline: usize,
    handler: usize,
) -> usize {
    let f = unsafe { &mut *(handler as *mut Box<dyn FnMut(&mut RetContext) -> usize>) };
    f(&mut RetContext { regs, trampoline })
}
