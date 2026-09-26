//! Scope-aware analysis of JavaScript and TypeScript sources that execute a
//! file through their own or the action's location.
//!
//! Location provenance follows resolved symbols, so an unrelated value that
//! shares a name with a located one does not inherit its provenance. A field
//! belongs to the object that holds it: a class, an object literal, or a
//! variable. A field of an object the analysis cannot identify matches every
//! field of that name.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentOperator, AssignmentTarget, BinaryOperator,
    BindingPattern, CallExpression, ClassElement, Expression, FormalParameters,
    IdentifierReference, ImportDeclarationSpecifier, MethodDefinitionKind, NumericLiteral,
    ObjectExpression, ObjectPropertyKind, PropertyKey, PropertyKind, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_semantic::{AstNodes, NodeId, Scoping, SemanticBuilder, SymbolFlags, SymbolId};
use oxc_span::{GetSpan, SourceType, Span};

use crate::audit_shell::shell_words;
use crate::audit_source::{
    ACTION_LOCATION, DYNAMIC_VALUE, LocatedDirectory, LocatedExecution, MAX_LOCATION_DEPTH,
    MAX_LOCATION_VALUE_BYTES, MAX_LOCATION_WORDS, SELF_FILE, SELF_LOCATION, ShellLocationState,
    ShellScan, SourceContext, SourceFileKind, UNRESOLVED_LOCATION, command_located_executions,
    dirname_location, is_location_derived, join_location, merge_location_values,
    shell_script_executions,
};

const EXECUTION_CALLS: &[&str] = &[
    "execSync",
    "execFileSync",
    "execFile",
    "exec",
    "spawnSync",
    "spawn",
    "fork",
    "getExecOutput",
    "execa",
    "execaSync",
    "execaCommand",
    "execaCommandSync",
    "execaNode",
];

/// Methods that store their arguments in the receiver.
const MUTATING_METHODS: &[&str] = &[
    "push", "unshift", "splice", "fill", "set", "add", "append", "prepend",
];

/// Execution options that cannot choose what runs, unlike `shell`,
/// `execPath`, `execArgv`, `env` or `input`; `cwd` is resolved separately.
const INERT_OPTIONS: &[&str] = &[
    "cwd",
    "encoding",
    "stdio",
    "timeout",
    "maxBuffer",
    "killSignal",
    "signal",
    "windowsHide",
    "windowsVerbatimArguments",
    "detached",
    "uid",
    "gid",
    "argv0",
    "silent",
    "failOnStdErr",
    "ignoreReturnCode",
    "delay",
    "listeners",
    "outStream",
    "errStream",
];

/// Names for the global object.
const GLOBAL_OBJECTS: &[&str] = &["globalThis", "global", "window", "self"];

/// Methods the language calls without naming them, so a location they
/// return reaches whatever uses the instance.
const IMPLICIT_METHODS: &[&str] = &["toString", "toJSON", "valueOf", "toLocaleString", "then"];

/// Functions that store their later arguments in their first.
const STORING_FUNCTIONS: &[&str] = &["assign", "defineProperty", "defineProperties"];

/// Names whose mention anywhere a value can come from draws on a location.
const LOCATION_NAMES: [&str; 3] = ["__dirname", "__filename", "GITHUB_ACTION_PATH"];

/// A regular expression's own properties and methods, which read it and
/// hand out nothing that reaches its prototype.
const REGEX_PROPERTIES: &[&str] = &[
    "exec",
    "test",
    "lastIndex",
    "source",
    "flags",
    "global",
    "ignoreCase",
    "multiline",
    "sticky",
    "unicode",
    "unicodeSets",
    "dotAll",
    "hasIndices",
    "toString",
];

/// Methods that read a regular expression they are given without being able
/// to replace its `exec`.
const REGEX_CONSUMERS: &[&str] = &[
    "replace",
    "replaceAll",
    "match",
    "matchAll",
    "split",
    "search",
];

/// Node's built-in modules, which a loader resolves ahead of any file,
/// except those that can replace or reach around the loader itself.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Built-in modules that can replace Node's module loader or run code
/// outside this analysis.
const LOADER_MODULES: &[&str] = &["module", "vm", "inspector", "repl"];

/// Code that bundlers pass to `eval` and `Function` to reach the loader or
/// the global object, which loads nothing itself.
const INERT_CODE: &[&str] = &["require", "this", "return this", "return this;"];

/// Runs the analysis in place of the command line: see `in_worker`.
pub(crate) const WORKER_ARGUMENT: &str = "--javascript-location-worker";

/// Parsing recurses once per level of nesting, at up to 2 KiB of stack each.
const WORKER_STACK_BYTES: usize = 256 << 20;

/// Analysis takes about a second for the largest bundles; a worker still
/// running long after that is treated as failed.
const WORKER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(serde::Serialize, serde::Deserialize)]
enum WorkerTask {
    Executions,
    BuiltinUse,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WorkerRequest {
    task: WorkerTask,
    path: String,
    code: String,
    context: SourceContext,
}

/// What a file visibly does to Node's module loader and built-in modules,
/// which the heuristic model of their normal behavior depends on.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct BuiltinUse {
    /// Whether it replaces or reaches around the loader: see
    /// `LoaderGuard::replaces`.
    pub(crate) replaces_loader: bool,
    /// Members it may replace on built-in modules, as `module:member` with
    /// the root of the module's name; `module:*` is any member.
    pub(crate) patched: Vec<String>,
}

/// See `BuiltinUse`. Code that cannot be read replaces the loader.
pub(crate) fn builtin_use(path: &str, code: &str) -> BuiltinUse {
    let request = WorkerRequest {
        task: WorkerTask::BuiltinUse,
        path: path.to_string(),
        code: code.to_string(),
        context: SourceContext::default(),
    };
    if cfg!(test) {
        return parsed_builtin_use(&request.path, &request.code);
    }
    in_worker(&request).unwrap_or(BuiltinUse {
        replaces_loader: true,
        patched: Vec::new(),
    })
}

fn parsed_builtin_use(path: &str, code: &str) -> BuiltinUse {
    let source_type = SourceType::from_path(path).unwrap_or_else(|_| SourceType::unambiguous());
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, code, source_type).parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        return BuiltinUse {
            replaces_loader: true,
            patched: Vec::new(),
        };
    }
    let semantic = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program)
        .semantic;
    let guard = LoaderGuard::new(semantic.nodes(), semantic.scoping());
    let mut builtin_use = BuiltinUse::default();
    for node in semantic.nodes().iter() {
        builtin_use.replaces_loader |= guard.replaces(node.id());
        if let Some((modules, member)) = guard.patches(node.id()) {
            for module in modules {
                let patch = format!("{module}:{}", member.unwrap_or("*"));
                if !builtin_use.patched.contains(&patch) {
                    builtin_use.patched.push(patch);
                }
            }
        }
    }
    builtin_use.patched.sort_unstable();
    builtin_use
}

/// Executions `code` performs through a location. `path` selects the
/// dialect; code without one parses as a script or module by its content.
pub(crate) fn located_executions(
    path: &str,
    code: &str,
    context: &SourceContext,
) -> Vec<LocatedExecution> {
    // Escapes can spell a name the raw text does not contain.
    let mentions_location = is_location_derived(code)
        || code.contains("import.meta")
        || code.contains("\\u")
        || code.contains("\\x")
        || LOCATION_NAMES
            .iter()
            .copied()
            .chain(context.environment.iter().map(|(name, _)| name.as_str()))
            .any(|token| code.contains(token));
    if context.directory == LocatedDirectory::Caller && !mentions_location {
        return Vec::new();
    }
    if cfg!(test) {
        return analyze(path, code, context);
    }
    in_worker(&WorkerRequest {
        task: WorkerTask::Executions,
        path: path.to_string(),
        code: code.to_string(),
        context: SourceContext {
            directory: context.directory.clone(),
            environment: context.environment.clone(),
            native_modules: context.native_modules,
            patched_builtins: context.patched_builtins.clone(),
        },
    })
    .unwrap_or_else(|| vec![LocatedExecution::unresolved(SourceFileKind::JavaScript)])
}

/// Parses and analyzes in a child process. No stack bounds nesting as deep
/// as a source file can hold, and an overflow aborts the process, so a child
/// that fails or outlives `WORKER_DEADLINE` gives no answer instead of
/// ending the scan.
fn in_worker<T: serde::de::DeserializeOwned>(request: &WorkerRequest) -> Option<T> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let request = serde_json::to_vec(request).ok()?;
    let mut child = Command::new(std::env::current_exe().ok()?)
        .arg(WORKER_ARGUMENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    // Each pipe has its own thread, so a worker that stops reading or
    // writing cannot hold the deadline off.
    let writer = std::thread::spawn(move || stdin.write_all(&request));
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).map(|_| output)
    });
    let deadline = Instant::now() + WORKER_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let written = writer.join();
    let output = reader.join();
    if !status?.success() || !matches!(written, Ok(Ok(()))) {
        return None;
    }
    serde_json::from_slice(&output.ok()?.ok()?).ok()
}

/// The worker side of `in_worker`.
pub(crate) fn run_worker() -> std::process::ExitCode {
    use std::io::{Read, Write};
    use std::process::ExitCode;

    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(request) = serde_json::from_slice::<WorkerRequest>(&input) else {
        return ExitCode::FAILURE;
    };
    let analysis = std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || match request.task {
            WorkerTask::Executions => {
                serde_json::to_value(analyze(&request.path, &request.code, &request.context))
            }
            WorkerTask::BuiltinUse => {
                serde_json::to_value(parsed_builtin_use(&request.path, &request.code))
            }
        });
    let Ok(Ok(Ok(answer))) = analysis.map(std::thread::JoinHandle::join) else {
        return ExitCode::FAILURE;
    };
    let mut stdout = std::io::stdout().lock();
    match serde_json::to_writer(&mut stdout, &answer).map(|()| stdout.flush()) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn analyze(path: &str, code: &str, context: &SourceContext) -> Vec<LocatedExecution> {
    let source_type = SourceType::from_path(path).unwrap_or_else(|_| SourceType::unambiguous());
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, code, source_type).parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        // Source that does not parse cleanly cannot be shown not to run
        // something through its location.
        return vec![LocatedExecution::unresolved(SourceFileKind::JavaScript)];
    }
    let semantic = SemanticBuilder::new()
        .with_build_nodes(true)
        .build(&parsed.program)
        .semantic;
    Analysis::new(semantic.nodes(), semantic.scoping(), context).executions()
}

fn builtin_module(specifier: &str) -> bool {
    match specifier.strip_prefix("node:") {
        Some(name) => !LOADER_MODULES.contains(&name),
        None => NODE_BUILTINS.contains(&specifier),
    }
}

/// The root of a built-in module's name, which its subpath modules share:
/// `fs` for `node:fs/promises`.
fn builtin_root(specifier: &str) -> &str {
    let name = specifier.strip_prefix("node:").unwrap_or(specifier);
    name.split('/').next().unwrap_or(name)
}

fn loader_module(specifier: &str) -> bool {
    LOADER_MODULES.contains(&specifier.strip_prefix("node:").unwrap_or(specifier))
}

/// A string literal, or a template literal with nothing substituted.
fn literal_text<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression.get_inner_expression() {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()
            .and_then(|quasi| quasi.value.cooked.as_ref())
            .map(|cooked| cooked.as_str()),
        _ => None,
    }
}

/// Bindings `process.binding` hands out that hold no loader or compiler.
const INERT_BINDINGS: &[&str] = &["buffer", "constants", "fs", "os", "util", "uv", "tty_wrap"];

/// The built-in modules each expression may hold, by its span.
type Holders<'a> = HashMap<(u32, u32), Vec<&'a str>>;

struct LoaderGuard<'s, 'a> {
    nodes: &'s AstNodes<'a>,
    scoping: &'s Scoping,
    /// Functions `copies_only` has judged.
    copiers: RefCell<HashMap<NodeId, bool>>,
    /// What `holders` found, once computed.
    holders: RefCell<Option<Holders<'a>>>,
    /// Identifiers by position, once `identifiers_within` has indexed them.
    identifiers: RefCell<Option<Vec<(u32, u32, NodeId)>>>,
    /// What `assigned` found for each variable.
    assigned: RefCell<HashMap<SymbolId, Vec<&'a Expression<'a>>>>,
    /// The calls to each function, once `calls_to` has indexed them.
    callers: RefCell<Option<HashMap<NodeId, Vec<NodeId>>>>,
}

impl<'s, 'a> LoaderGuard<'s, 'a> {
    fn new(nodes: &'s AstNodes<'a>, scoping: &'s Scoping) -> Self {
        Self {
            nodes,
            scoping,
            copiers: RefCell::default(),
            holders: RefCell::default(),
            identifiers: RefCell::default(),
            assigned: RefCell::default(),
            callers: RefCell::default(),
        }
    }

    fn symbol(&self, reference: &IdentifierReference) -> Option<SymbolId> {
        reference
            .reference_id
            .get()
            .and_then(|reference| self.scoping.get_reference(reference).symbol_id())
    }

    fn span(&self, node: NodeId) -> Span {
        self.nodes.kind(node).span()
    }

    /// Whether `node` is what a call calls, through `(0, f)` indirection.
    fn called(&self, node: NodeId) -> bool {
        self.nodes
            .ancestor_ids(node)
            .take(3)
            .any(|ancestor| match self.nodes.kind(ancestor) {
                AstKind::CallExpression(call) => inner(&call.callee).span() == self.span(node),
                AstKind::NewExpression(call) => inner(&call.callee).span() == self.span(node),
                _ => false,
            })
    }

    fn compared(&self, node: NodeId) -> bool {
        match self.nodes.parent_kind(node) {
            AstKind::BinaryExpression(binary) => {
                binary.operator.is_equality()
                    || binary.operator == BinaryOperator::Instanceof
                        && binary.right.span() == self.span(node)
            }
            AstKind::UnaryExpression(unary) => unary.operator == UnaryOperator::Typeof,
            _ => false,
        }
    }

    /// The property a member read of `node` names.
    fn read_property(&self, node: NodeId) -> Option<&'a str> {
        match self.nodes.parent_kind(node) {
            AstKind::StaticMemberExpression(member) if member.object.span() == self.span(node) => {
                Some(member.property.name.as_str())
            }
            _ => None,
        }
    }

    /// The one value a variable holds: its initializer, or the only
    /// assignment to one declared without it.
    fn bound_value(&self, symbol: SymbolId) -> Option<&'a Expression<'a>> {
        let AstKind::VariableDeclarator(declarator) =
            self.nodes.kind(self.scoping.symbol_declaration(symbol))
        else {
            return None;
        };
        let mut writes = self
            .scoping
            .get_resolved_references(symbol)
            .filter(|reference| reference.is_write());
        match (&declarator.init, writes.next(), writes.next()) {
            (Some(init), None, _) => Some(init),
            (None, Some(write), None) => match self.nodes.parent_kind(write.node_id()) {
                AstKind::AssignmentExpression(assignment) => Some(&assignment.right),
                _ => None,
            },
            _ => None,
        }
    }

    /// `createRequire` imported from `node:module`, or read from a `module`
    /// object that is used for nothing else.
    fn factory(&self, callee: &'a Expression<'a>, depth: usize) -> bool {
        match inner(callee) {
            Expression::Identifier(identifier) => self.symbol(identifier).is_some_and(|symbol| {
                let declaration = self.scoping.symbol_declaration(symbol);
                matches!(self.nodes.kind(declaration), AstKind::ImportSpecifier(specifier)
                    if specifier.imported.name().as_str() == "createRequire")
                    && matches!(self.nodes.parent_kind(declaration), AstKind::ImportDeclaration(import)
                        if matches!(import.source.value.as_str(), "module" | "node:module"))
            }),
            expression => expression_property(expression).is_some_and(|(object, name)| {
                name == "createRequire"
                    && matches!(inner(object), Expression::Identifier(module)
                        if self.symbol(module).is_some_and(|symbol| self.module_object(symbol, depth + 1)))
            }),
        }
    }

    /// A variable holding the `module` built-in a loader returned.
    fn module_object(&self, symbol: SymbolId, depth: usize) -> bool {
        depth <= MAX_LOCATION_DEPTH
            && self.bound_value(symbol).is_some_and(|value| {
                matches!(inner(value), Expression::CallExpression(call)
                    if self.loads(call, depth + 1)
                        && self.specifier(call).is_some_and(|specifier| matches!(specifier, "module" | "node:module")))
            })
    }

    /// A variable holding a loader `createRequire` returned.
    fn loader(&self, symbol: SymbolId, depth: usize) -> bool {
        depth <= MAX_LOCATION_DEPTH
            && self.bound_value(symbol).is_some_and(|value| {
                matches!(inner(value), Expression::CallExpression(call)
                    if self.factory(&call.callee, depth + 1))
            })
    }

    /// Whether a call loads a module: through `require`, a loader
    /// `createRequire` returned, or `eval("require")`.
    fn loads(&self, call: &'a CallExpression<'a>, depth: usize) -> bool {
        match inner(&call.callee) {
            Expression::Identifier(identifier) => match self.symbol(identifier) {
                None => identifier.name.as_str() == "require",
                Some(symbol) => self.loader(symbol, depth),
            },
            Expression::CallExpression(factory) => {
                self.factory(&factory.callee, depth)
                    || matches!(inner(&factory.callee), Expression::Identifier(eval)
                        if eval.name.as_str() == "eval" && self.symbol(eval).is_none())
            }
            _ => false,
        }
    }

    /// The built-in modules, by the root of their name, each expression may
    /// hold, keyed by its span: every module followed from where it is loaded
    /// by a literal name or imported, through members, variables bound or
    /// destructured from it, parameters of the functions it is passed to,
    /// what those functions return, and what a `wrapper` returns given it.
    fn holders(&self) -> std::cell::Ref<'_, Holders<'a>> {
        if self.holders.borrow().is_none() {
            let holders = self.follow_modules();
            *self.holders.borrow_mut() = Some(holders);
        }
        std::cell::Ref::map(self.holders.borrow(), |holders| {
            holders.as_ref().expect("computed above")
        })
    }

    fn follow_modules(&self) -> Holders<'a> {
        enum Holder {
            Node(NodeId),
            Symbol(SymbolId),
        }
        let mut pending: Vec<(Holder, &'a str)> = Vec::new();
        for node in self.nodes.iter() {
            match node.kind() {
                AstKind::CallExpression(call) if self.loads(call, 0) => {
                    if let Some(specifier) = self
                        .specifier(call)
                        .filter(|specifier| builtin_module(specifier))
                    {
                        pending.push((Holder::Node(node.id()), builtin_root(specifier)));
                    }
                }
                AstKind::ImportNamespaceSpecifier(specifier) => {
                    if let AstKind::ImportDeclaration(import) = self.nodes.parent_kind(node.id())
                        && builtin_module(import.source.value.as_str())
                        && let Some(symbol) = specifier.local.symbol_id.get()
                    {
                        pending.push((
                            Holder::Symbol(symbol),
                            builtin_root(import.source.value.as_str()),
                        ));
                    }
                }
                AstKind::ImportDefaultSpecifier(specifier) => {
                    if let AstKind::ImportDeclaration(import) = self.nodes.parent_kind(node.id())
                        && builtin_module(import.source.value.as_str())
                        && let Some(symbol) = specifier.local.symbol_id.get()
                    {
                        pending.push((
                            Holder::Symbol(symbol),
                            builtin_root(import.source.value.as_str()),
                        ));
                    }
                }
                _ => {}
            }
        }
        let mut holders: Holders<'a> = HashMap::new();
        let mut symbols: HashMap<SymbolId, Vec<&'a str>> = HashMap::new();
        let bind = |span: Span, pending: &mut Vec<(Holder, &'a str)>, module: &'a str| {
            for (_, _, node) in self.identifiers_within(span) {
                if let AstKind::BindingIdentifier(binding) = self.nodes.kind(node)
                    && let Some(symbol) = binding.symbol_id.get()
                {
                    pending.push((Holder::Symbol(symbol), module));
                }
            }
        };
        while let Some((holder, module)) = pending.pop() {
            let node = match holder {
                Holder::Symbol(symbol) => {
                    let modules = symbols.entry(symbol).or_default();
                    if modules.contains(&module) {
                        continue;
                    }
                    modules.push(module);
                    for reference in self.scoping.get_resolved_references(symbol) {
                        if reference.is_read() {
                            pending.push((Holder::Node(reference.node_id()), module));
                        }
                    }
                    continue;
                }
                Holder::Node(node) => node,
            };
            let span = self.span(node);
            let modules = holders.entry((span.start, span.end)).or_default();
            if modules.contains(&module) {
                continue;
            }
            modules.push(module);
            let parent = self.nodes.parent_id(node);
            match self.nodes.kind(parent) {
                AstKind::StaticMemberExpression(member) if member.object.span() == span => {
                    pending.push((Holder::Node(parent), module));
                }
                AstKind::ComputedMemberExpression(member) if member.object.span() == span => {
                    pending.push((Holder::Node(parent), module));
                }
                AstKind::ParenthesizedExpression(_)
                | AstKind::TSAsExpression(_)
                | AstKind::TSSatisfiesExpression(_)
                | AstKind::TSNonNullExpression(_)
                | AstKind::TSTypeAssertion(_)
                | AstKind::LogicalExpression(_) => pending.push((Holder::Node(parent), module)),
                AstKind::ConditionalExpression(conditional) if conditional.test.span() != span => {
                    pending.push((Holder::Node(parent), module));
                }
                AstKind::SequenceExpression(sequence)
                    if sequence
                        .expressions
                        .last()
                        .is_some_and(|last| last.span() == span) =>
                {
                    pending.push((Holder::Node(parent), module));
                }
                AstKind::VariableDeclarator(declarator)
                    if declarator
                        .init
                        .as_ref()
                        .is_some_and(|init| init.span() == span) =>
                {
                    bind(declarator.id.span(), &mut pending, module);
                }
                AstKind::AssignmentExpression(assignment) if assignment.right.span() == span => {
                    if let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left
                        && let Some(symbol) = self.symbol(target)
                    {
                        pending.push((Holder::Symbol(symbol), module));
                    }
                }
                AstKind::CallExpression(call) => {
                    if let Some(index) = call
                        .arguments
                        .iter()
                        .position(|argument| argument.span() == span)
                    {
                        if index == 0 && self.wrapper(call) {
                            pending.push((Holder::Node(parent), module));
                        }
                        for (function, shift) in self.callee_functions(call) {
                            let Some(parameters) = self.parameters_of(function) else {
                                continue;
                            };
                            let Some(position) = index.checked_sub(shift) else {
                                continue;
                            };
                            match parameters.items.get(position) {
                                Some(parameter) => {
                                    bind(parameter.pattern.span(), &mut pending, module);
                                }
                                None => {
                                    if let Some(rest) = &parameters.rest {
                                        bind(rest.span, &mut pending, module);
                                    }
                                }
                            }
                        }
                    }
                }
                AstKind::ReturnStatement(_) => {
                    if let Some(function) = self.enclosing_function(parent) {
                        for call in self.calls_to(function) {
                            pending.push((Holder::Node(call), module));
                        }
                    }
                }
                AstKind::ArrowFunctionExpression(arrow)
                    if arrow
                        .body
                        .as_expression()
                        .is_some_and(|body| body.span() == span) =>
                {
                    for call in self.calls_to(parent) {
                        pending.push((Holder::Node(call), module));
                    }
                }
                _ => {}
            }
        }
        holders
    }

    /// The modules an expression may hold: see `holders`.
    fn modules_of(&self, expression: &Expression) -> Vec<&'a str> {
        let span = inner(expression).span();
        self.holders()
            .get(&(span.start, span.end))
            .cloned()
            .unwrap_or_default()
    }

    /// Binding and reference identifiers inside `span`, in source order.
    fn identifiers_within(&self, span: Span) -> Vec<(u32, u32, NodeId)> {
        let mut identifiers = self.identifiers.borrow_mut();
        let identifiers = identifiers.get_or_insert_with(|| {
            let mut identifiers: Vec<(u32, u32, NodeId)> = self
                .nodes
                .iter()
                .filter(|node| {
                    matches!(
                        node.kind(),
                        AstKind::BindingIdentifier(_) | AstKind::IdentifierReference(_)
                    )
                })
                .map(|node| {
                    let span = node.kind().span();
                    (span.start, span.end, node.id())
                })
                .collect();
            identifiers.sort_unstable();
            identifiers
        });
        let first = identifiers.partition_point(|(start, _, _)| *start < span.start);
        identifiers[first..]
            .iter()
            .take_while(|(start, _, _)| *start < span.end)
            .filter(|(_, end, _)| *end <= span.end)
            .copied()
            .collect()
    }

    fn parameters_of(&self, function: NodeId) -> Option<&'a FormalParameters<'a>> {
        match self.nodes.kind(function) {
            AstKind::Function(function) => Some(&function.params),
            AstKind::ArrowFunctionExpression(function) => Some(&function.params),
            _ => None,
        }
    }

    fn enclosing_function(&self, node: NodeId) -> Option<NodeId> {
        self.nodes.ancestor_ids(node).find(|ancestor| {
            matches!(
                self.nodes.kind(*ancestor),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
    }

    /// The functions of this file a call may run, with how far `call` shifts
    /// the arguments they receive: one a variable or declaration may name,
    /// one called at once, a method of an object literal the receiver
    /// variable may hold, or one of those through `call`.
    fn callee_functions(&self, call: &'a CallExpression<'a>) -> Vec<(NodeId, usize)> {
        let mut functions = self.functions_of(&call.callee, 0);
        if let Some(function) = through_call(call) {
            functions.extend(self.functions_of(function, 1));
        }
        functions
    }

    fn functions_of(&self, callee: &'a Expression<'a>, shift: usize) -> Vec<(NodeId, usize)> {
        let function = |value: &'a Expression<'a>| match inner(value) {
            Expression::FunctionExpression(function) => Some((function.node_id.get(), shift)),
            Expression::ArrowFunctionExpression(function) => Some((function.node_id.get(), shift)),
            _ => None,
        };
        match inner(callee) {
            Expression::Identifier(identifier) => {
                let Some(symbol) = self.symbol(identifier) else {
                    return Vec::new();
                };
                self.scoping
                    .symbol_declarations(symbol)
                    .filter(|declaration| {
                        matches!(self.nodes.kind(*declaration), AstKind::Function(_))
                    })
                    .map(|declaration| (declaration, shift))
                    .chain(self.assigned(symbol).into_iter().filter_map(function))
                    .collect()
            }
            callee @ (Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)) => function(callee).into_iter().collect(),
            callee => {
                let Some((object, name)) = expression_property(callee) else {
                    return Vec::new();
                };
                let Expression::Identifier(holder) = inner(object) else {
                    return Vec::new();
                };
                let Some(symbol) = self.symbol(holder) else {
                    return Vec::new();
                };
                self.assigned(symbol)
                    .into_iter()
                    .filter_map(|value| match inner(value) {
                        Expression::ObjectExpression(literal) => Some(literal),
                        _ => None,
                    })
                    .flat_map(|literal| &literal.properties)
                    .filter_map(|property| match property {
                        ObjectPropertyKind::ObjectProperty(property)
                            if key_name(&property.key) == Some(name) =>
                        {
                            function(&property.value)
                        }
                        _ => None,
                    })
                    .collect()
            }
        }
    }

    /// Every value a variable may hold: what each declaration of it
    /// initializes it to and each assignment to it writes.
    fn assigned(&self, symbol: SymbolId) -> Vec<&'a Expression<'a>> {
        if let Some(values) = self.assigned.borrow().get(&symbol) {
            return values.clone();
        }
        let mut values = Vec::new();
        for declaration in self.scoping.symbol_declarations(symbol) {
            if let AstKind::VariableDeclarator(declarator) = self.nodes.kind(declaration)
                && let BindingPattern::BindingIdentifier(_) = declarator.id
            {
                values.extend(&declarator.init);
            }
        }
        for reference in self.scoping.get_resolved_references(symbol) {
            if reference.is_write()
                && let AstKind::AssignmentExpression(assignment) =
                    self.nodes.parent_kind(reference.node_id())
            {
                values.push(&assignment.right);
            }
        }
        self.assigned.borrow_mut().insert(symbol, values.clone());
        values
    }

    /// Whether a call hands its first argument to a `copies_only` function
    /// and passes nothing else but literals.
    fn wrapper(&self, call: &'a CallExpression<'a>) -> bool {
        let Expression::Identifier(callee) = inner(&call.callee) else {
            return false;
        };
        call.arguments.iter().skip(1).all(|argument| {
            matches!(
                argument.as_expression().map(inner),
                Some(
                    Expression::StringLiteral(_)
                        | Expression::NumericLiteral(_)
                        | Expression::BooleanLiteral(_)
                        | Expression::NullLiteral(_)
                )
            )
        }) && self
            .symbol(callee)
            .and_then(|symbol| self.defined_function(symbol))
            .is_some_and(|function| self.copies_only(function, 0))
    }

    /// The function a declaration or a variable bound once names.
    fn defined_function(&self, symbol: SymbolId) -> Option<NodeId> {
        let declaration = self.scoping.symbol_declaration(symbol);
        if let AstKind::Function(_) = self.nodes.kind(declaration) {
            return (!self
                .scoping
                .get_resolved_references(symbol)
                .any(|reference| reference.is_write()))
            .then_some(declaration);
        }
        match self.bound_value(symbol).map(inner) {
            Some(Expression::ArrowFunctionExpression(function)) => Some(function.node_id.get()),
            Some(Expression::FunctionExpression(function)) => Some(function.node_id.get()),
            _ => None,
        }
    }

    /// Whether a function can hand out no function of this file but getters
    /// that read what its own variables hold, as bundlers' interop helpers
    /// copy a module: every function inside it is such a getter, it uses no
    /// `this`, and it reads nothing from outside but `Object` and its methods
    /// held in variables, and other such functions. It may still give a
    /// module's members other names, so a copy is trusted only for a module
    /// nothing patches.
    fn copies_only(&self, function: NodeId, depth: usize) -> bool {
        if let Some(judged) = self.copiers.borrow().get(&function) {
            return *judged;
        }
        // A function that reaches itself is judged not to copy.
        self.copiers.borrow_mut().insert(function, false);
        let span = self.span(function);
        // Nodes are numbered as they are visited, so a function's own come
        // right after it.
        let judged = depth <= MAX_LOCATION_DEPTH
            && self
                .nodes
                .iter()
                .skip(function.index())
                .take_while(|node| contains(span, node.kind().span()))
                .all(|node| match node.kind() {
                    AstKind::ThisExpression(_) => false,
                    AstKind::Function(_) => node.id() == function,
                    AstKind::ArrowFunctionExpression(_) => {
                        node.id() == function || self.forwards(node.id(), span)
                    }
                    AstKind::IdentifierReference(reference) => match self.symbol(reference) {
                        None => matches!(reference.name.as_str(), "Object" | "undefined"),
                        Some(symbol) => {
                            contains(span, self.span(self.scoping.symbol_declaration(symbol)))
                                || self.bound_value(symbol).is_some_and(|value| {
                                    matches!(expression_property(inner(value)), Some((object, _))
                                        if self.global(object, "Object")
                                            || matches!(expression_property(inner(object)), Some((root, "prototype"))
                                                if self.global(root, "Object")))
                                })
                                || self
                                    .defined_function(symbol)
                                    .is_some_and(|helper| self.copies_only(helper, depth + 1))
                        }
                    },
                    _ => true,
                });
        self.copiers.borrow_mut().insert(function, judged);
        judged
    }

    fn global(&self, expression: &Expression, name: &str) -> bool {
        matches!(expression.get_inner_expression(), Expression::Identifier(identifier)
            if identifier.name.as_str() == name && self.symbol(identifier).is_none())
    }

    /// Whether a function is a getter `() => from[key]` reading what a
    /// variable inside `span` holds.
    fn forwards(&self, function: NodeId, span: Span) -> bool {
        let AstKind::ArrowFunctionExpression(arrow) = self.nodes.kind(function) else {
            return false;
        };
        arrow.params.items.is_empty()
            && arrow.params.rest.is_none()
            && arrow.body.as_expression().is_some_and(|body| {
                matches!(body.get_inner_expression(), Expression::ComputedMemberExpression(member)
                if matches!(member.object.get_inner_expression(), Expression::Identifier(object)
                    if self.symbol(object).is_some_and(|symbol| {
                        contains(span, self.span(self.scoping.symbol_declaration(symbol)))
                    })))
            })
    }

    /// The `Object` or `Reflect` function a callee is, directly or through a
    /// variable, when it writes its first argument.
    fn stores(&self, callee: &'a Expression<'a>) -> Option<&'a str> {
        let member = match inner(callee) {
            Expression::Identifier(identifier) => inner(
                self.symbol(identifier)
                    .and_then(|symbol| self.bound_value(symbol))?,
            ),
            member => member,
        };
        expression_property(member).and_then(|(object, name)| {
            (matches!(object.get_inner_expression(), Expression::Identifier(root)
                if self.symbol(root).is_none() && matches!(root.name.as_str(), "Object" | "Reflect"))
                && matches!(
                    name,
                    "assign" | "defineProperty" | "defineProperties" | "setPrototypeOf" | "set"
                ))
            .then_some(name)
        })
    }

    /// The built-in modules and member a node may replace, `None` for any
    /// member: a value that may be a function written onto a member of one,
    /// or one of `stores` given one.
    fn patches(&self, node: NodeId) -> Option<(Vec<&'a str>, Option<&'a str>)> {
        match self.nodes.kind(node) {
            AstKind::AssignmentExpression(assignment) => {
                let (object, name) = expression_target(&assignment.left)?;
                let modules = self.modules_of(object);
                (!modules.is_empty()
                    && !matches!(
                        inner(&assignment.right),
                        Expression::StringLiteral(_)
                            | Expression::NumericLiteral(_)
                            | Expression::BooleanLiteral(_)
                            | Expression::NullLiteral(_)
                            | Expression::TemplateLiteral(_)
                            | Expression::BinaryExpression(_)
                            | Expression::UnaryExpression(_)
                    ))
                .then_some((modules, name))
            }
            AstKind::CallExpression(call) => {
                let (function, shift) = match self.stores(&call.callee) {
                    Some(function) => (function, 0),
                    None => (self.stores(through_call(call)?)?, 1),
                };
                let mut arguments = call
                    .arguments
                    .iter()
                    .skip(shift)
                    .map(Argument::as_expression);
                let modules = self.modules_of(arguments.next().flatten()?);
                if modules.is_empty() {
                    return None;
                }
                Some((
                    modules,
                    match function {
                        "defineProperty" | "set" => {
                            arguments.next().flatten().and_then(literal_text)
                        }
                        _ => None,
                    },
                ))
            }
            _ => None,
        }
    }

    /// The calls that may run a function: the reverse of `callee_functions`,
    /// so what a function returns reaches every call its parameters are
    /// bound from.
    fn calls_to(&self, function: NodeId) -> Vec<NodeId> {
        let mut callers = self.callers.borrow_mut();
        let callers = callers.get_or_insert_with(|| {
            let mut callers: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
            for node in self.nodes.iter() {
                if let AstKind::CallExpression(call) = node.kind() {
                    for (function, _) in self.callee_functions(call) {
                        callers.entry(function).or_default().push(node.id());
                    }
                }
            }
            callers
        });
        callers.get(&function).cloned().unwrap_or_default()
    }

    fn specifier(&self, call: &'a CallExpression<'a>) -> Option<&'a str> {
        call.arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(literal_text)
    }

    /// A path built from a literal relative prefix, as bundlers load their
    /// own chunks: it can only name a file.
    fn relative(expression: &Expression) -> bool {
        let prefix = match expression.get_inner_expression() {
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                return Self::relative(&binary.left)
                    || literal_text(&binary.left)
                        .is_some_and(|text| text.starts_with("./") || text.starts_with("../"));
            }
            Expression::TemplateLiteral(template) => template
                .quasis
                .first()
                .and_then(|quasi| quasi.value.cooked.as_ref())
                .map(|cooked| cooked.as_str()),
            expression => literal_text(expression),
        };
        prefix.is_some_and(|text| text.starts_with("./") || text.starts_with("../"))
    }

    /// Whether a call to `eval` or `Function` runs code other than
    /// `INERT_CODE`.
    fn evaluates(arguments: &[Argument]) -> bool {
        !(arguments
            .last()
            .and_then(Argument::as_expression)
            .and_then(literal_text)
            .is_some_and(|code| INERT_CODE.contains(&code.trim()))
            && arguments
                .iter()
                .all(|argument| argument.as_expression().and_then(literal_text).is_some()))
    }

    /// Whether a node visibly replaces or reaches around Node's module
    /// loader: it takes more than `createRequire` from `node:module`; loads
    /// `vm`, `inspector` or `repl`, or `module` for anything but
    /// `createRequire`; loads or imports what it does not spell out, other
    /// than a path relative to itself; lets a loader, `require` or `module`
    /// escape where the cache or resolution can be changed; names a loader
    /// internal; writes through a `constructor`; or evaluates code other than
    /// `INERT_CODE`. Concealed replacement, such as reaching `Function`
    /// through a computed key, is a documented limit of the model rather than
    /// something this finds.
    fn replaces(&self, node: NodeId) -> bool {
        match self.nodes.kind(node) {
            AstKind::ImportDeclaration(import) if !import.import_kind.is_type() => {
                let source = import.source.value.as_str();
                let only_create_require = import.specifiers.as_ref().is_some_and(|specifiers| {
                    specifiers.iter().all(|specifier| {
                        matches!(specifier, ImportDeclarationSpecifier::ImportSpecifier(specifier)
                            if specifier.import_kind.is_type()
                                || specifier.imported.name().as_str() == "createRequire")
                    })
                });
                source.starts_with("data:")
                    || loader_module(source)
                        && !(matches!(source, "module" | "node:module") && only_create_require)
            }
            AstKind::ExportFromDeclaration(export) => loader_module(export.source.value.as_str()),
            AstKind::ExportAllDeclaration(export) => loader_module(export.source.value.as_str()),
            AstKind::ImportExpression(import) => match literal_text(&import.source) {
                Some(source) => loader_module(source) || source.starts_with("data:"),
                None => !Self::relative(&import.source),
            },
            AstKind::CallExpression(call) if self.loads(call, 0) => match self.specifier(call) {
                // `module` itself only to make another loader.
                Some("module" | "node:module") => !match self.nodes.parent_kind(node) {
                    AstKind::VariableDeclarator(declarator) => match &declarator.id {
                        BindingPattern::BindingIdentifier(binding) => binding
                            .symbol_id
                            .get()
                            .is_some_and(|symbol| self.module_object(symbol, 0)),
                        _ => false,
                    },
                    _ => false,
                },
                Some(specifier) => loader_module(specifier),
                None => !call
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .is_some_and(Self::relative),
            },
            // A loader not called or bound where it is made escapes.
            AstKind::CallExpression(call) if self.factory(&call.callee, 0) => {
                !match self.nodes.parent_kind(node) {
                    AstKind::CallExpression(load) => load.callee.span() == call.span,
                    AstKind::VariableDeclarator(_) | AstKind::AssignmentExpression(_) => true,
                    _ => false,
                }
            }
            AstKind::CallExpression(call) => {
                matches!(inner(&call.callee), Expression::Identifier(callee)
                if self.symbol(callee).is_none() && matches!(callee.name.as_str(), "eval" | "Function")
                    && Self::evaluates(&call.arguments))
            }
            AstKind::NewExpression(call) => {
                matches!(inner(&call.callee), Expression::Identifier(callee)
                if self.symbol(callee).is_none() && callee.name.as_str() == "Function"
                    && Self::evaluates(&call.arguments))
            }
            AstKind::IdentifierReference(reference) => match self.symbol(reference) {
                None => self.escapes_global(node, reference.name.as_str()),
                Some(symbol) if self.loader(symbol, 0) => {
                    !self.called(node)
                        && !self.compared(node)
                        && !reference.reference_id.get().is_some_and(|reference| {
                            self.scoping.get_reference(reference).is_write()
                        })
                }
                Some(symbol) if self.module_object(symbol, 0) => {
                    !(self.read_property(node) == Some("createRequire")
                        && self.called(self.nodes.parent_id(node)))
                }
                Some(_) => false,
            },
            AstKind::StaticMemberExpression(member) => match member.property.name.as_str() {
                "syncBuiltinESMExports" | "getBuiltinModule" => true,
                "createRequire" => !matches!(inner(&member.object), Expression::Identifier(module)
                    if self.symbol(module).is_some_and(|symbol| self.module_object(symbol, 0))),
                _ => false,
            },
            AstKind::StringLiteral(literal) => {
                !matches!(self.nodes.parent_kind(node), AstKind::ImportSpecifier(_))
                    && matches!(
                        literal.value.as_str(),
                        "syncBuiltinESMExports" | "getBuiltinModule" | "createRequire"
                    )
            }
            AstKind::AssignmentExpression(assignment) => expression_target(&assignment.left)
                .is_some_and(|(object, _)| {
                    expression_property(object.get_inner_expression())
                        .is_some_and(|(_, name)| name == "constructor")
                }),
            _ => false,
        }
    }

    /// Whether a global that reaches the loader or evaluates code is used
    /// beyond the forms bundles use it in.
    fn escapes_global(&self, node: NodeId, name: &str) -> bool {
        let property = self.read_property(node);
        match name {
            "eval" => !self.called(node),
            // Only the shims that read Function's methods without calling
            // them on Function: `Function.prototype` other than its
            // `constructor`, a detached `Function.bind`, and
            // `Function.call.bind(f)`.
            "Function" => {
                let member = self.nodes.parent_id(node);
                !self.called(node)
                    && !self.compared(node)
                    && !match property {
                        Some("prototype") => member_property(self.nodes.parent_kind(member))
                            .is_none_or(|(_, name)| name != "constructor"),
                        Some("bind") => match self.nodes.parent_kind(member) {
                            AstKind::VariableDeclarator(declarator) => declarator
                                .init
                                .as_ref()
                                .is_some_and(|init| init.span() == self.span(member)),
                            AstKind::AssignmentExpression(assignment) => {
                                assignment.right.span() == self.span(member)
                            }
                            _ => false,
                        },
                        Some("call") => {
                            self.read_property(member) == Some("bind")
                                && self.called(self.nodes.parent_id(member))
                        }
                        _ => false,
                    }
            }
            "require" => {
                !self.called(node)
                    && !self.compared(node)
                    && property != Some("resolve")
                    && !(property == Some("main") && self.compared(self.nodes.parent_id(node)))
            }
            "module" => {
                !self.compared(node)
                    && !matches!(
                        property,
                        Some("exports" | "id" | "filename" | "loaded" | "path" | "paths")
                    )
            }
            "process" => match property {
                Some("mainModule" | "dlopen" | "_linkedBinding") => true,
                Some("binding") => {
                    let member = self.nodes.parent_id(node);
                    !matches!(self.nodes.parent_kind(member), AstKind::CallExpression(call)
                        if call.callee.span() == self.span(member)
                            && call.arguments.first().and_then(Argument::as_expression).and_then(literal_text)
                                .is_some_and(|binding| INERT_BINDINGS.contains(&binding)))
                }
                _ => false,
            },
            name if GLOBAL_OBJECTS.contains(&name) => {
                matches!(property, Some("eval" | "Function" | "require" | "module"))
            }
            _ => false,
        }
    }
}

/// The object a field belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Owner<'a> {
    /// A variable, or the class whose instances a variable holds.
    Symbol(SymbolId),
    /// A class or object literal not bound to a variable.
    Node(NodeId),
    /// A global, with the property of it that holds the field, so that
    /// `process.env` and `process.versions` stay apart. The global object's
    /// own fields belong to `globalThis`.
    Global(&'a str, Option<&'a str>),
    /// A global under a key this analysis cannot name.
    AnyGlobal,
    /// What `this` refers to outside a class or object literal method: any
    /// object the function is called on.
    Receiver,
    Unknown,
}

/// What a located value reaches. A field without a name is every field of
/// its owner.
#[derive(Clone, Copy)]
enum Taint<'a> {
    Symbol(SymbolId),
    Field(Owner<'a>, Option<&'a str>),
    Node(NodeId),
    /// An expression whose object a located value was stored into.
    Holder(&'a Expression<'a>),
}

/// A write to a field: its owner, and the value of a plain assignment.
type Store<'a> = (Owner<'a>, Option<&'a Expression<'a>>);

struct Analysis<'s, 'a> {
    nodes: &'s AstNodes<'a>,
    scoping: &'s Scoping,
    context: &'s SourceContext,
    /// Identifier references and bindings by source position.
    identifiers: Vec<(u32, u32, NodeId)>,
    /// `this` expressions by source position.
    receivers: Vec<(u32, NodeId)>,
    /// Functions a call reaches through the symbol it names; a class's is
    /// its constructor.
    functions: HashMap<SymbolId, Vec<NodeId>>,
    /// Functions a method call reaches, by name and owner.
    methods: HashMap<&'a str, Vec<(Owner<'a>, NodeId)>>,
    /// Member expressions, destructured properties and undeclared names by
    /// the field they name.
    members: HashMap<&'a str, Vec<NodeId>>,
    /// Member expressions through a key this analysis cannot name.
    unnamed_members: Vec<NodeId>,
    /// Getters and setters, which the language calls without naming them.
    accessors: HashSet<NodeId>,
    /// Getters and setters by the field they define and the object they
    /// define it on.
    getters: HashMap<Option<&'a str>, Vec<(Owner<'a>, NodeId)>>,
    stores: HashMap<&'a str, Vec<Store<'a>>>,
    /// Fields that storing calls, prototype changes or computed writes may
    /// have replaced, by owner; a field without a name is any field.
    redefined: HashSet<(Owner<'a>, Option<&'a str>)>,
    /// Property names this file defines on any object.
    defined: HashSet<&'a str>,
    /// Property names object literals and classes define.
    literal_names: HashSet<&'a str>,
    /// Location names this file may rebind, which then no longer evaluate
    /// to the location: `__dirname`, `__filename` or `import.meta`.
    rebound: HashSet<&'static str>,
    /// Globals under which this file may store an existing object, so that
    /// a read through one may reach another global's fields; with a key
    /// this analysis cannot name, any global.
    inexact_globals: HashSet<&'a str>,
    every_global_inexact: bool,
    tainted_nodes: HashSet<NodeId>,
    tainted_symbols: HashSet<SymbolId>,
    tainted_fields: HashSet<(Owner<'a>, Option<&'a str>)>,
    regexp_exposed: bool,
    /// Spans of tainted nodes, sorted, for containment queries.
    tainted_spans: Vec<(u32, u32)>,
    values: RefCell<HashMap<SymbolId, String>>,
    field_values: RefCell<HashMap<(Owner<'a>, &'a str), String>>,
    words: RefCell<HashMap<SymbolId, Vec<String>>>,
    arguments: RefCell<HashMap<NodeId, Option<Vec<Option<&'a Expression<'a>>>>>>,
    /// Recognizes interop wrappers: see `LoaderGuard::wrapper`.
    guard: LoaderGuard<'s, 'a>,
}

fn contains(outer: Span, inner: Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

/// The object and static property name of a member expression.
fn member_property<'a>(kind: AstKind<'a>) -> Option<(&'a Expression<'a>, &'a str)> {
    match kind {
        AstKind::StaticMemberExpression(member) => {
            Some((&member.object, member.property.name.as_str()))
        }
        AstKind::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(key) => Some((&member.object, key.value.as_str())),
            _ => None,
        },
        AstKind::PrivateFieldExpression(member) => {
            Some((&member.object, member.field.name.as_str()))
        }
        _ => None,
    }
}

/// The function a call runs through `call`, which receives the arguments
/// after the first.
fn through_call<'a>(call: &'a CallExpression<'a>) -> Option<&'a Expression<'a>> {
    match expression_property(inner(&call.callee)) {
        Some((function, "call")) => Some(function),
        _ => None,
    }
}

fn expression_property<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a str)> {
    match expression {
        Expression::StaticMemberExpression(member) => {
            Some((&member.object, member.property.name.as_str()))
        }
        Expression::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(key) => Some((&member.object, key.value.as_str())),
            _ => None,
        },
        Expression::PrivateFieldExpression(member) => {
            Some((&member.object, member.field.name.as_str()))
        }
        _ => None,
    }
}

fn key_name<'a>(key: &'a PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(name) => Some(name.name.as_str()),
        PropertyKey::PrivateIdentifier(name) => Some(name.name.as_str()),
        PropertyKey::StringLiteral(name) => Some(name.value.as_str()),
        PropertyKey::NumericLiteral(number) => numeric_name(number),
        _ => None,
    }
}

/// The property name a number literal is, when it is written as one, as
/// bundlers key their modules.
fn numeric_name<'a>(number: &NumericLiteral<'a>) -> Option<&'a str> {
    number.raw.map(|raw| raw.as_str()).filter(|raw| {
        raw.bytes().all(|byte| byte.is_ascii_digit()) && (*raw == "0" || !raw.starts_with('0'))
    })
}

/// An expression without parentheses, type assertions, `await` or `(0, f)`
/// indirection.
fn inner<'a>(expression: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut current = expression.get_inner_expression();
    loop {
        current = match current {
            Expression::SequenceExpression(sequence) => match sequence.expressions.last() {
                Some(last) => last.get_inner_expression(),
                None => return current,
            },
            Expression::AwaitExpression(awaited) => awaited.argument.get_inner_expression(),
            _ => return current,
        };
    }
}

/// Whether an expression creates a value that holds no existing object: a
/// primitive, a function or class, or a literal object or array of such
/// values.
fn is_fresh(expression: &Expression) -> bool {
    is_fresh_within(expression, 0)
}

fn is_fresh_within(expression: &Expression, depth: usize) -> bool {
    if depth > MAX_LOCATION_DEPTH {
        return false;
    }
    match expression.get_inner_expression() {
        Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::BinaryExpression(_)
        | Expression::UnaryExpression(_)
        | Expression::UpdateExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_)
        | Expression::TemplateLiteral(_) => true,
        Expression::ObjectExpression(object) => object.properties.iter().all(|property| {
            matches!(property, ObjectPropertyKind::ObjectProperty(property)
                if property.kind == PropertyKind::Init
                    && is_fresh_within(&property.value, depth + 1))
        }),
        Expression::ArrayExpression(array) => array.elements.iter().all(|element| {
            element
                .as_expression()
                .is_some_and(|element| is_fresh_within(element, depth + 1))
        }),
        _ => false,
    }
}

impl<'s, 'a> Analysis<'s, 'a> {
    fn new(nodes: &'s AstNodes<'a>, scoping: &'s Scoping, context: &'s SourceContext) -> Self {
        let mut analysis = Self {
            nodes,
            scoping,
            context,
            identifiers: Vec::new(),
            receivers: Vec::new(),
            functions: HashMap::new(),
            methods: HashMap::new(),
            members: HashMap::new(),
            unnamed_members: Vec::new(),
            accessors: HashSet::new(),
            getters: HashMap::new(),
            stores: HashMap::new(),
            redefined: HashSet::new(),
            defined: HashSet::new(),
            literal_names: HashSet::new(),
            rebound: HashSet::new(),
            inexact_globals: HashSet::new(),
            every_global_inexact: false,
            tainted_nodes: HashSet::new(),
            tainted_symbols: HashSet::new(),
            tainted_fields: HashSet::new(),
            regexp_exposed: false,
            tainted_spans: Vec::new(),
            values: RefCell::default(),
            field_values: RefCell::default(),
            words: RefCell::default(),
            arguments: RefCell::default(),
            guard: LoaderGuard::new(nodes, scoping),
        };
        analysis.index();
        analysis.regexp_exposed = analysis.exposes_regexp();
        analysis.trace();
        analysis
    }

    fn span(&self, node: NodeId) -> Span {
        self.nodes.kind(node).span()
    }

    fn resolved(&self, reference: &IdentifierReference) -> Option<SymbolId> {
        reference
            .reference_id
            .get()
            .and_then(|reference| self.scoping.get_reference(reference).symbol_id())
    }

    fn is_global(&self, expression: &Expression, name: &str) -> bool {
        matches!(expression.get_inner_expression(), Expression::Identifier(identifier)
            if identifier.name.as_str() == name && self.resolved(identifier).is_none())
    }

    fn index(&mut self) {
        let mut callables = Vec::new();
        let mut stores: Vec<(&'a str, Store<'a>)> = Vec::new();
        for node in self.nodes.iter() {
            let id = node.id();
            match node.kind() {
                AstKind::IdentifierReference(reference) => {
                    self.identifiers
                        .push((reference.span.start, reference.span.end, id));
                    // An undeclared name is a field of the global object.
                    if self.resolved(reference).is_none() {
                        self.members
                            .entry(reference.name.as_str())
                            .or_default()
                            .push(id);
                        let written = reference.reference_id.get().is_some_and(|reference| {
                            self.scoping.get_reference(reference).is_write()
                        });
                        let fresh = matches!(self.nodes.parent_kind(id), AstKind::AssignmentExpression(assignment)
                            if assignment.operator == AssignmentOperator::Assign
                                && is_fresh(&assignment.right));
                        if written && !fresh {
                            self.inexact_globals.insert(reference.name.as_str());
                        }
                        if written {
                            self.rebind(reference.name.as_str());
                        }
                    }
                }
                AstKind::ImportMeta(_) => {
                    let written = matches!(self.nodes.parent_kind(id),
                        AstKind::StaticMemberExpression(_) | AstKind::ComputedMemberExpression(_)
                            if self.store_of(self.nodes.parent_id(id)).is_some());
                    if written || !self.names_further_field(id) {
                        self.rebind("import.meta");
                    }
                }
                AstKind::BindingIdentifier(binding) => {
                    self.identifiers
                        .push((binding.span.start, binding.span.end, id));
                }
                AstKind::ThisExpression(this) => self.receivers.push((this.span.start, id)),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => {
                    if !matches!(self.nodes.parent_kind(id), AstKind::MethodDefinition(method)
                        if method.kind == MethodDefinitionKind::Constructor)
                    {
                        callables.push((id, id));
                    }
                    let accessor = match self.nodes.parent_kind(id) {
                        AstKind::MethodDefinition(method)
                            if matches!(
                                method.kind,
                                MethodDefinitionKind::Get | MethodDefinitionKind::Set
                            ) =>
                        {
                            Some((self.class_owner_of(id), key_name(&method.key)))
                        }
                        AstKind::ObjectProperty(property)
                            if property.kind != PropertyKind::Init =>
                        {
                            let literal = self.nodes.parent_id(self.nodes.parent_id(id));
                            Some((self.object_owner(literal), key_name(&property.key)))
                        }
                        _ => None,
                    };
                    if let Some((owner, name)) = accessor {
                        self.accessors.insert(id);
                        self.getters.entry(name).or_default().push((owner, id));
                    }
                    let defined = match self.nodes.parent_kind(id) {
                        AstKind::ObjectProperty(property)
                            if key_name(&property.key)
                                .is_some_and(|key| matches!(key, "get" | "set")) =>
                        {
                            self.described(self.nodes.parent_id(self.nodes.parent_id(id)))
                        }
                        AstKind::CallExpression(call) => expression_property(inner(&call.callee))
                            .filter(|(_, name)| {
                                matches!(*name, "__defineGetter__" | "__defineSetter__")
                            })
                            .map(|(object, _)| {
                                (
                                    self.store_owner(object),
                                    call.arguments
                                        .first()
                                        .and_then(Argument::as_expression)
                                        .and_then(|name| self.constant_key(name)),
                                )
                            }),
                        _ => None,
                    };
                    if let Some((owner, name)) = defined {
                        self.getters.entry(name).or_default().push((owner, id));
                    }
                }
                AstKind::Class(class) => {
                    let constructor = class.body.body.iter().find_map(|element| match element {
                        ClassElement::MethodDefinition(method)
                            if method.kind == MethodDefinitionKind::Constructor =>
                        {
                            Some(method.value.node_id.get())
                        }
                        _ => None,
                    });
                    if let Some(constructor) = constructor {
                        callables.push((id, constructor));
                    }
                }
                AstKind::BindingProperty(property) => {
                    if let Some(name) = key_name(&property.key) {
                        self.members.entry(name).or_default().push(id);
                    }
                }
                AstKind::AssignmentTargetPropertyIdentifier(property) => {
                    self.members
                        .entry(property.binding.name.as_str())
                        .or_default()
                        .push(id);
                }
                AstKind::AssignmentTargetPropertyProperty(property) => {
                    if let Some(name) = key_name(&property.name) {
                        self.members.entry(name).or_default().push(id);
                    }
                }
                AstKind::PropertyDefinition(property) => {
                    if let (Some(name), Some(value)) = (key_name(&property.key), &property.value) {
                        stores.push((name, (self.class_owner_of(id), Some(value))));
                    }
                }
                kind => {
                    let parts = match kind {
                        AstKind::ComputedMemberExpression(member) => {
                            Some((&member.object, self.constant_key(&member.expression)))
                        }
                        kind => member_property(kind).map(|(object, name)| (object, Some(name))),
                    };
                    match parts {
                        Some((object, Some(name))) => {
                            self.members.entry(name).or_default().push(id);
                            if let Some(value) = self.store_of(id) {
                                stores.push((name, (self.field_owner(object), value)));
                            }
                        }
                        Some((_, None)) => self.unnamed_members.push(id),
                        None => {}
                    }
                }
            }
        }
        self.identifiers.sort_unstable();
        self.receivers.sort_unstable();
        for node in self.nodes.iter() {
            let redefinitions = self.redefinitions(node.id());
            self.defined
                .extend(redefinitions.iter().filter_map(|(_, name)| *name));
            self.redefined.extend(redefinitions);
            let literal = match node.kind() {
                AstKind::ObjectProperty(property) => key_name(&property.key),
                AstKind::MethodDefinition(method) => key_name(&method.key),
                AstKind::PropertyDefinition(property) => key_name(&property.key),
                AstKind::AccessorProperty(property) => key_name(&property.key),
                _ => None,
            };
            self.defined.extend(literal);
            self.literal_names.extend(literal);
            if let AstKind::CallExpression(call) = node.kind() {
                if let Some((object, name)) = expression_property(inner(&call.callee))
                    && MUTATING_METHODS.contains(&name)
                {
                    let owner = self.store_owner(object);
                    self.store_under_global(owner, None);
                }
                // Direct `eval` code shares the module's scope; code it cannot
                // see leaves coverage incomplete elsewhere.
                if self.is_global(&call.callee, "eval") {
                    for argument in &call.arguments {
                        let texts: Vec<&str> = match argument.as_expression().map(inner) {
                            Some(Expression::StringLiteral(literal)) => {
                                vec![literal.value.as_str()]
                            }
                            Some(Expression::TemplateLiteral(template)) => template
                                .quasis
                                .iter()
                                .map(|quasi| {
                                    quasi
                                        .value
                                        .cooked
                                        .as_ref()
                                        .map_or(quasi.value.raw.as_str(), |cooked| cooked.as_str())
                                })
                                .collect(),
                            _ => continue,
                        };
                        for name in ["__dirname", "__filename"] {
                            if texts.iter().any(|text| text.contains(name)) {
                                self.rebind(name);
                            }
                        }
                    }
                }
            }
        }
        for (owner, name) in self.redefined.clone() {
            self.store_under_global(owner, name);
        }
        let stored: Vec<&'a str> = stores.iter().map(|(name, _)| *name).collect();
        self.defined.extend(stored);
        for (name, (owner, value)) in stores {
            if !value.is_some_and(is_fresh) {
                self.store_under_global(owner, Some(name));
            }
            self.stores.entry(name).or_default().push((owner, value));
        }
        for (value, function) in callables {
            for taint in self.value_bindings(value) {
                match taint {
                    Taint::Symbol(symbol) => {
                        self.functions.entry(symbol).or_default().push(function);
                    }
                    Taint::Field(owner, Some(name)) => {
                        self.methods
                            .entry(name)
                            .or_default()
                            .push((owner, function));
                    }
                    Taint::Field(_, None) | Taint::Node(_) | Taint::Holder(_) => {}
                }
            }
        }
    }

    fn rebind(&mut self, name: &str) {
        if let Some(name) = ["__dirname", "__filename", "import.meta"]
            .into_iter()
            .find(|location| *location == name)
        {
            self.rebound.insert(name);
        }
    }

    /// Whether this file may write the environment variable `name`.
    fn environment_rebound(&self, name: &str) -> bool {
        let environment = Owner::Global("process", Some("env"));
        self.stores
            .get(name)
            .into_iter()
            .flatten()
            .any(|(owner, _)| self.holds(*owner, true, environment))
            || self.redefined.iter().any(|(owner, field)| {
                field.is_none_or(|field| field == name) && self.holds(*owner, true, environment)
            })
    }

    /// Records that this file stores what may be an existing object into
    /// `name` of `owner`, when that is under a global.
    fn store_under_global(&mut self, owner: Owner<'a>, name: Option<&'a str>) {
        match owner {
            Owner::Global("globalThis", None) => match name {
                Some(name) => {
                    self.inexact_globals.insert(name);
                }
                None => self.every_global_inexact = true,
            },
            Owner::Global(root, _) => {
                self.inexact_globals.insert(root);
            }
            Owner::AnyGlobal => self.every_global_inexact = true,
            _ => {}
        }
    }

    /// Whether a read through a global finds only that global's own fields.
    fn exact_global(&self, root: &str) -> bool {
        root == "globalThis" || !self.every_global_inexact && !self.inexact_globals.contains(root)
    }

    /// The fields a node may replace other than by a plain store: a storing
    /// or prototype-changing call, a write through a computed key, or a
    /// prototype write.
    fn redefinitions(&self, node: NodeId) -> Vec<(Owner<'a>, Option<&'a str>)> {
        let literal = |argument: Option<&'a Argument<'a>>| match argument
            .and_then(Argument::as_expression)
            .map(inner)
        {
            Some(Expression::StringLiteral(key)) => Some(key.value.as_str()),
            _ => None,
        };
        let keys = |source: Option<&'a Argument<'a>>| -> Vec<Option<&'a str>> {
            match source
                .and_then(Argument::as_expression)
                .and_then(|source| self.object_literal(source))
            {
                Some(object) => object
                    .properties
                    .iter()
                    .map(|property| match property {
                        ObjectPropertyKind::ObjectProperty(property) if !property.computed => {
                            key_name(&property.key)
                        }
                        _ => None,
                    })
                    .collect(),
                None => vec![None],
            }
        };
        match self.nodes.kind(node) {
            AstKind::CallExpression(call) => {
                let Some((receiver, name)) = self.callee_name(&call.callee) else {
                    return Vec::new();
                };
                let target = || call.arguments.first().and_then(Argument::as_expression);
                let (target, names) = match name {
                    "__defineGetter__" | "__defineSetter__" => {
                        (receiver, vec![literal(call.arguments.first())])
                    }
                    "defineProperty" | "set" => (target(), vec![literal(call.arguments.get(1))]),
                    "defineProperties" => (target(), keys(call.arguments.get(1))),
                    "assign" => (
                        target(),
                        call.arguments
                            .iter()
                            .skip(1)
                            .flat_map(|source| keys(Some(source)))
                            .collect(),
                    ),
                    "setPrototypeOf" => (target(), vec![None]),
                    _ => return Vec::new(),
                };
                let Some(target) = target else {
                    return Vec::new();
                };
                let owner = self.store_owner(target);
                names.into_iter().map(|name| (owner, name)).collect()
            }
            AstKind::ComputedMemberExpression(member)
                if self.store_of(node).is_some()
                    && !matches!(&member.expression, Expression::StringLiteral(key)
                        if key.value.as_str() != "__proto__") =>
            {
                vec![(self.store_owner(&member.object), None)]
            }
            AstKind::StaticMemberExpression(member)
                if member.property.name.as_str() == "__proto__"
                    && self.store_of(node).is_some() =>
            {
                vec![(self.store_owner(&member.object), None)]
            }
            _ => Vec::new(),
        }
    }

    /// Whether this file may define a property of this name on some object,
    /// including through a computed key.
    fn defines(&self, name: &str) -> bool {
        self.defined.contains(name) || self.redefined.iter().any(|(_, name)| name.is_none())
    }

    /// Whether a member expression is written: `Some(Some(value))` for a
    /// plain assignment, `Some(None)` for any other write.
    fn store_of(&self, member: NodeId) -> Option<Option<&'a Expression<'a>>> {
        let span = self.span(member);
        match self.nodes.parent_kind(member) {
            AstKind::AssignmentExpression(assignment) if assignment.left.span() == span => Some(
                (assignment.operator == AssignmentOperator::Assign).then_some(&assignment.right),
            ),
            AstKind::UpdateExpression(_)
            | AstKind::ArrayAssignmentTarget(_)
            | AstKind::AssignmentTargetRest(_)
            | AstKind::AssignmentTargetWithDefault(_)
            | AstKind::AssignmentTargetPropertyProperty(_) => Some(None),
            AstKind::ForInStatement(statement) if statement.left.span() == span => Some(None),
            AstKind::ForOfStatement(statement) if statement.left.span() == span => Some(None),
            _ => None,
        }
    }

    /// The owner of fields read through `object`: whatever the root of its
    /// member chain names. Nested objects share their root's fields, and a
    /// root that may alias other objects, such as a parameter, is unknown.
    fn owner_of(&self, object: &'a Expression<'a>) -> Owner<'a> {
        self.root_owner(object, false)
    }

    /// The owner of fields written, or methods called, through `object`.
    /// A write through `this` outside a method may be to any object.
    fn store_owner(&self, object: &'a Expression<'a>) -> Owner<'a> {
        self.root_owner(object, true)
    }

    /// The owner of a field written through `object`. An object nested in
    /// another may be any object stored there, unless the outer one is a
    /// literal that only ever holds fresh values.
    fn field_owner(&self, object: &'a Expression<'a>) -> Owner<'a> {
        match self.store_owner(object) {
            Owner::Symbol(symbol) if self.nested(object) && !self.exact_object(symbol) => {
                Owner::Unknown
            }
            Owner::Node(_) if self.nested(object) => Owner::Unknown,
            owner => owner,
        }
    }

    /// Whether `object` is a field of another object, directly or through
    /// variables aliasing one.
    fn nested(&self, object: &'a Expression<'a>) -> bool {
        let mut current = inner(object);
        for _ in 0..=MAX_LOCATION_DEPTH {
            if self.member_parts(current).is_some() {
                return true;
            }
            match current {
                Expression::Identifier(identifier) => {
                    match self
                        .resolved(identifier)
                        .and_then(|symbol| self.alias(symbol))
                    {
                        Some(alias) => current = alias,
                        None => return false,
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// Whether a variable's object is a literal of fresh values whose
    /// nested objects never leave it and are only given fresh values.
    fn exact_object(&self, symbol: SymbolId) -> bool {
        self.initializer(symbol).is_some_and(|init| {
            matches!(
                inner(init),
                Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
            ) && is_fresh(init)
        }) && self.confined(symbol, 0)
    }

    fn confined(&self, symbol: SymbolId, depth: usize) -> bool {
        if depth > MAX_LOCATION_DEPTH {
            return false;
        }
        self.scoping
            .get_resolved_references(symbol)
            .filter(|reference| reference.is_read())
            .all(|reference| {
                let mut current = reference.node_id();
                loop {
                    if let Some(alias) = self.aliased_by(current) {
                        return self.confined(alias, depth + 1);
                    }
                    let parent = self.nodes.parent_id(current);
                    if !self
                        .member_parts_of(parent)
                        .is_some_and(|(object, _)| object.span() == self.span(current))
                    {
                        return false;
                    }
                    match self.store_of(parent) {
                        Some(Some(value)) => return is_fresh(value),
                        Some(None) => return false,
                        None if self.called(parent).is_some() => return false,
                        None => current = parent,
                    }
                }
            })
    }

    fn root_owner(&self, object: &'a Expression<'a>, store: bool) -> Owner<'a> {
        let mut current = inner(object);
        // The properties from the outermost to the one on the root.
        let mut properties = Vec::new();
        let mut aliases = 0;
        loop {
            if let Some((object, name)) = self.member_parts(current) {
                properties.push(name);
                current = inner(object);
                continue;
            }
            // `g.process.env` after `const g = globalThis.globalThis` is
            // `process.env`.
            if let Expression::Identifier(identifier) = current
                && let Some(alias) = self
                    .resolved(identifier)
                    .and_then(|symbol| self.alias(symbol))
            {
                aliases += 1;
                if aliases > MAX_LOCATION_DEPTH {
                    return Owner::Unknown;
                }
                current = alias;
                continue;
            }
            return match current {
                // A receiver's nested objects are values like any other,
                // located once the field holding them is.
                Expression::ThisExpression(this) => match self.this_owner(this.node_id.get()) {
                    Owner::Receiver if store || !properties.is_empty() => Owner::Unknown,
                    owner => owner,
                },
                // A field under an unknown key of the global object may be
                // any global's.
                Expression::Identifier(identifier) if self.is_global_object(identifier) => {
                    while properties
                        .last()
                        .is_some_and(|name| name.is_some_and(|name| GLOBAL_OBJECTS.contains(&name)))
                    {
                        properties.pop();
                    }
                    match properties.pop() {
                        Some(Some(root)) => Owner::Global(root, properties.pop().flatten()),
                        Some(None) => Owner::AnyGlobal,
                        None => Owner::Global("globalThis", None),
                    }
                }
                Expression::Identifier(identifier) => match self.resolved(identifier) {
                    Some(symbol) => self.symbol_owner(symbol),
                    None => Owner::Global(identifier.name.as_str(), properties.pop().flatten()),
                },
                Expression::NewExpression(construction) => match inner(&construction.callee) {
                    Expression::Identifier(callee) => self
                        .resolved(callee)
                        .filter(|class| self.constructs(*class))
                        .map_or(Owner::Unknown, Owner::Symbol),
                    _ => Owner::Unknown,
                },
                _ => Owner::Unknown,
            };
        }
    }

    /// The expression a variable only ever aliases: another variable, a
    /// member of one, or `this`.
    fn alias(&self, symbol: SymbolId) -> Option<&'a Expression<'a>> {
        let flags = self.scoping.symbol_flags(symbol);
        if flags.is_function() || flags.is_class() || flags.intersects(SymbolFlags::Import) {
            return None;
        }
        self.initializer(symbol).map(inner).filter(|init| {
            matches!(
                init,
                Expression::Identifier(_)
                    | Expression::StaticMemberExpression(_)
                    | Expression::ComputedMemberExpression(_)
                    | Expression::PrivateFieldExpression(_)
                    | Expression::ThisExpression(_)
            )
        })
    }

    /// Whether an identifier names the global object.
    fn is_global_object(&self, identifier: &IdentifierReference) -> bool {
        self.resolved(identifier).is_none() && GLOBAL_OBJECTS.contains(&identifier.name.as_str())
    }

    /// The object and field a member expression reads, resolving a constant
    /// computed key; `None` is a field this analysis cannot name.
    fn member_parts(
        &self,
        expression: &'a Expression<'a>,
    ) -> Option<(&'a Expression<'a>, Option<&'a str>)> {
        match expression {
            Expression::ComputedMemberExpression(member) => {
                Some((&member.object, self.constant_key(&member.expression)))
            }
            expression => {
                expression_property(expression).map(|(object, name)| (object, Some(name)))
            }
        }
    }

    /// The string a computed key always is: a literal, or a variable only
    /// ever holding one.
    fn constant_key(&self, key: &'a Expression<'a>) -> Option<&'a str> {
        self.constant_key_within(key, 0)
    }

    fn constant_key_within(&self, key: &'a Expression<'a>, depth: usize) -> Option<&'a str> {
        if depth > MAX_LOCATION_DEPTH {
            return None;
        }
        match inner(key) {
            Expression::StringLiteral(key) => Some(key.value.as_str()),
            Expression::NumericLiteral(number) => numeric_name(number),
            Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
                .quasis
                .first()
                .and_then(|quasi| quasi.value.cooked.as_ref())
                .map(|cooked| cooked.as_str()),
            Expression::Identifier(identifier) => self.constant_key_within(
                self.resolved(identifier)
                    .and_then(|symbol| self.initializer(symbol))?,
                depth + 1,
            ),
            _ => None,
        }
    }

    fn property_key(&self, key: &'a PropertyKey<'a>) -> Option<&'a str> {
        key_name(key).or_else(|| key.as_expression().and_then(|key| self.constant_key(key)))
    }

    /// Whether a field written through `store` may be what a read through
    /// `read` finds, where `named` is whether the read names the field: the
    /// same owner, a write through an object this analysis cannot identify,
    /// a named read through a receiver, which may be any object, or a
    /// global's field written or read without knowing which of its
    /// properties holds it. A receiver's other reads find a location once
    /// a located object is bound to it. Code can reach the global object
    /// without naming it, so a global's field is found by name through any
    /// object but a global holding only its own fields, and one under an
    /// unknown key of the global object through any object this analysis
    /// cannot identify.
    fn holds(&self, store: Owner<'a>, named: bool, read: Owner<'a>) -> bool {
        store == read
            || store == Owner::Unknown
            || read == Owner::Receiver && named
            || match (store, read) {
                (Owner::Global(left, left_property), Owner::Global(right, right_property)) => {
                    left == right && (left_property.is_none() || right_property.is_none())
                        || named && !self.exact_global(right)
                }
                (Owner::AnyGlobal, Owner::Global(..) | Owner::Unknown | Owner::Receiver)
                | (Owner::Global(..), Owner::AnyGlobal)
                | (Owner::Global("globalThis", None), Owner::Unknown | Owner::Receiver) => true,
                // An object this file creates holds another global's object
                // only if that is stored into it, which makes it hold the
                // global's located fields or read a property on its path.
                (Owner::Global("globalThis", None) | Owner::AnyGlobal, _)
                | (Owner::Global(..), Owner::Unknown) => named,
                _ => false,
            }
    }

    /// The object a variable holds: its own when it creates one, or the
    /// class of an instance it creates.
    fn symbol_owner(&self, symbol: SymbolId) -> Owner<'a> {
        let flags = self.scoping.symbol_flags(symbol);
        if flags.is_function() || flags.is_class() || flags.intersects(SymbolFlags::Import) {
            return Owner::Symbol(symbol);
        }
        match self.initializer(symbol).map(inner) {
            Some(Expression::NewExpression(construction)) => match inner(&construction.callee) {
                Expression::Identifier(callee) => self
                    .resolved(callee)
                    .filter(|class| self.constructs(*class))
                    .map_or(Owner::Symbol(symbol), Owner::Symbol),
                _ => Owner::Symbol(symbol),
            },
            Some(
                Expression::ObjectExpression(_)
                | Expression::ArrayExpression(_)
                | Expression::ClassExpression(_)
                | Expression::FunctionExpression(_)
                | Expression::ArrowFunctionExpression(_),
            ) => Owner::Symbol(symbol),
            _ => Owner::Unknown,
        }
    }

    fn is_class(&self, symbol: SymbolId) -> bool {
        self.scoping.symbol_flags(symbol).is_class()
            || self
                .initializer(symbol)
                .is_some_and(|init| matches!(inner(init), Expression::ClassExpression(_)))
    }

    /// Whether `new` through a variable makes an instance of a class or
    /// function in this file, which shares that class's or function's
    /// prototype methods.
    fn constructs(&self, symbol: SymbolId) -> bool {
        self.is_class(symbol)
            || self.scoping.symbol_flags(symbol).is_function()
            || self
                .initializer(symbol)
                .is_some_and(|init| matches!(inner(init), Expression::FunctionExpression(_)))
    }

    /// What `this` refers to at `node`.
    fn this_owner(&self, node: NodeId) -> Owner<'a> {
        let mut child = node;
        for ancestor in self.nodes.ancestor_ids(node) {
            match self.nodes.kind(ancestor) {
                AstKind::Function(_) => {
                    return match self.nodes.parent_kind(ancestor) {
                        AstKind::MethodDefinition(_) => self.class_owner_of(ancestor),
                        AstKind::ObjectProperty(_) => {
                            self.object_owner(self.nodes.parent_id(self.nodes.parent_id(ancestor)))
                        }
                        _ => Owner::Receiver,
                    };
                }
                AstKind::PropertyDefinition(property)
                    if property
                        .value
                        .as_ref()
                        .is_some_and(|value| value.span() == self.span(child)) =>
                {
                    return self.class_owner_of(ancestor);
                }
                AstKind::StaticBlock(_) | AstKind::AccessorProperty(_) => {
                    return self.class_owner_of(ancestor);
                }
                _ => {}
            }
            child = ancestor;
        }
        Owner::Receiver
    }

    /// The owner of the class enclosing `node`.
    fn class_owner_of(&self, node: NodeId) -> Owner<'a> {
        let Some(class) = self
            .nodes
            .ancestor_ids(node)
            .find(|ancestor| matches!(self.nodes.kind(*ancestor), AstKind::Class(_)))
        else {
            return Owner::Unknown;
        };
        self.value_owner(class)
    }

    fn object_owner(&self, object: NodeId) -> Owner<'a> {
        if matches!(self.nodes.kind(object), AstKind::ObjectExpression(_)) {
            self.value_owner(object)
        } else {
            Owner::Unknown
        }
    }

    /// The variable a class or object literal is bound to, or the value
    /// itself.
    fn value_owner(&self, value: NodeId) -> Owner<'a> {
        if let AstKind::Class(class) = self.nodes.kind(value)
            && let Some(symbol) = class.id.as_ref().and_then(|id| id.symbol_id.get())
        {
            return Owner::Symbol(symbol);
        }
        let mut child = value;
        for parent in self.nodes.ancestor_ids(value) {
            match self.nodes.kind(parent) {
                AstKind::ParenthesizedExpression(_)
                | AstKind::TSAsExpression(_)
                | AstKind::TSSatisfiesExpression(_) => child = parent,
                AstKind::VariableDeclarator(declarator)
                    if declarator
                        .init
                        .as_ref()
                        .is_some_and(|init| init.span() == self.span(child)) =>
                {
                    if let BindingPattern::BindingIdentifier(binding) = &declarator.id
                        && let Some(symbol) = binding.symbol_id.get()
                    {
                        return Owner::Symbol(symbol);
                    }
                    break;
                }
                _ => break,
            }
        }
        Owner::Node(value)
    }

    /// The owner a member expression or destructured property reads from.
    fn read_owner(&self, node: NodeId) -> Owner<'a> {
        match self.nodes.kind(node) {
            AstKind::IdentifierReference(_) => return Owner::Global("globalThis", None),
            AstKind::ComputedMemberExpression(member) => return self.owner_of(&member.object),
            kind => {
                if let Some((object, _)) = member_property(kind) {
                    return self.owner_of(object);
                }
            }
        }
        let pattern = self.nodes.parent_id(node);
        match self.nodes.parent_kind(pattern) {
            AstKind::VariableDeclarator(declarator)
                if declarator.id.span() == self.span(pattern) =>
            {
                declarator
                    .init
                    .as_ref()
                    .map_or(Owner::Unknown, |init| self.owner_of(init))
            }
            AstKind::AssignmentExpression(assignment)
                if assignment.left.span() == self.span(pattern) =>
            {
                self.owner_of(&assignment.right)
            }
            _ => Owner::Unknown,
        }
    }

    /// What holds a located field under a global as a whole: a read naming
    /// the global object or a property on the path to the field, unless it
    /// reads that path and only names a further field of it, and the `this`
    /// of a function stored on the path.
    fn global_holders(&self, owner: Owner<'a>) -> Vec<NodeId> {
        let global = Owner::Global("globalThis", None);
        let mut path: Vec<(&str, Owner<'a>)> =
            GLOBAL_OBJECTS.iter().map(|name| (*name, global)).collect();
        if let Owner::Global(root, property) = owner
            && root != "globalThis"
        {
            path.push((root, global));
            if let Some(property) = property {
                path.push((property, Owner::Global(root, None)));
            }
        }
        let mut reads: Vec<(NodeId, bool)> = path
            .iter()
            .flat_map(|(name, exact)| {
                self.members
                    .get(name)
                    .into_iter()
                    .flatten()
                    .map(|read| (*read, self.read_owner(*read) == *exact))
            })
            .collect();
        let mut holders = Vec::new();
        let mut seen = HashSet::new();
        while let Some((read, exact)) = reads.pop() {
            if !seen.insert(read) || exact && self.names_further_field(read) {
                continue;
            }
            if exact && let Some(alias) = self.aliased_by(read) {
                // Reads through a variable that only aliases the path are
                // resolved like the path itself.
                reads.extend(
                    self.scoping
                        .get_resolved_references(alias)
                        .filter(|reference| reference.is_read())
                        .map(|reference| (reference.node_id(), true)),
                );
                continue;
            }
            holders.push(read);
        }
        let mut receivers = Vec::new();
        for (method, function) in self.methods.values().flatten() {
            if matches!(method, Owner::AnyGlobal | Owner::Global("globalThis", None))
                || matches!(method, Owner::Global(..)) && self.holds(owner, false, *method)
            {
                self.this_references(*function, &mut receivers);
            }
        }
        holders.extend(receivers.into_iter().filter_map(|taint| match taint {
            Taint::Node(node) => Some(node),
            _ => None,
        }));
        holders
    }

    /// Whether a read is only used to read named fields of it, as in `x.y`,
    /// `x.y()` or `const { y } = x`, and not as a value.
    fn names_further_field(&self, read: NodeId) -> bool {
        if let AstKind::BindingProperty(property) = self.nodes.kind(read) {
            return matches!(&property.value, BindingPattern::ObjectPattern(pattern)
                if pattern.rest.is_none());
        }
        let span = self.span(read);
        match self.nodes.parent_kind(read) {
            AstKind::StaticMemberExpression(member) => member.object.span() == span,
            AstKind::ComputedMemberExpression(member) => member.object.span() == span,
            AstKind::PrivateFieldExpression(member) => member.object.span() == span,
            AstKind::VariableDeclarator(declarator) => {
                declarator
                    .init
                    .as_ref()
                    .is_some_and(|init| init.span() == span)
                    && matches!(&declarator.id, BindingPattern::ObjectPattern(pattern)
                        if pattern.rest.is_none())
            }
            AstKind::AssignmentExpression(assignment) => {
                assignment.right.span() == span
                    && matches!(&assignment.left, AssignmentTarget::ObjectAssignmentTarget(target)
                        if target.rest.is_none())
            }
            _ => false,
        }
    }

    /// The variable a read initializes when that variable only aliases it.
    fn aliased_by(&self, read: NodeId) -> Option<SymbolId> {
        let span = self.span(read);
        let symbol = match self.nodes.parent_kind(read) {
            AstKind::VariableDeclarator(declarator) => match &declarator.id {
                BindingPattern::BindingIdentifier(binding) => binding.symbol_id.get(),
                _ => None,
            },
            AstKind::AssignmentExpression(assignment) => match &assignment.left {
                AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                    self.resolved(identifier)
                }
                _ => None,
            },
            _ => None,
        }?;
        self.alias(symbol)
            .is_some_and(|alias| alias.span() == span)
            .then_some(symbol)
    }

    fn field_tainted(&self, owner: Owner<'a>, name: &'a str) -> bool {
        self.tainted_fields
            .iter()
            .any(|(store, field)| match field {
                Some(field) => *field == name && self.holds(*store, true, owner),
                None => self.holds(*store, false, owner),
            })
    }

    /// What a function or class value is bound to: its own name, the
    /// variable or field that holds it, or the call it is an argument of,
    /// whose result may be what it returns.
    fn value_bindings(&self, value: NodeId) -> Vec<Taint<'a>> {
        let mut taints = Vec::new();
        match self.nodes.kind(value) {
            AstKind::Function(function) => {
                if let Some(symbol) = function.id.as_ref().and_then(|id| id.symbol_id.get()) {
                    taints.push(Taint::Symbol(symbol));
                }
            }
            AstKind::Class(class) => {
                if let Some(symbol) = class.id.as_ref().and_then(|id| id.symbol_id.get()) {
                    taints.push(Taint::Symbol(symbol));
                }
            }
            _ => {}
        }
        let mut child = value;
        for parent in self.nodes.ancestor_ids(value) {
            let span = self.span(child);
            match self.nodes.kind(parent) {
                AstKind::ParenthesizedExpression(_)
                | AstKind::TSAsExpression(_)
                | AstKind::TSSatisfiesExpression(_)
                | AstKind::TSNonNullExpression(_)
                | AstKind::TSTypeAssertion(_) => {
                    child = parent;
                    continue;
                }
                AstKind::VariableDeclarator(declarator) => {
                    if declarator
                        .init
                        .as_ref()
                        .is_some_and(|init| init.span() == span)
                    {
                        taints.extend(self.symbols_in(declarator.id.span()));
                    }
                }
                AstKind::AssignmentExpression(assignment) => {
                    if assignment.right.span() == span {
                        match expression_target(&assignment.left) {
                            Some((object, name)) => {
                                taints.push(Taint::Field(self.store_owner(object), name));
                            }
                            None => taints.extend(self.symbols_in(assignment.left.span())),
                        }
                    }
                }
                // A computed key, such as `Symbol.toPrimitive`, may be any
                // field.
                AstKind::ObjectProperty(property) => {
                    if property.value.span() == span {
                        let owner = self.object_owner(self.nodes.parent_id(parent));
                        taints.push(Taint::Field(owner, self.property_key(&property.key)));
                    }
                }
                AstKind::MethodDefinition(method) => {
                    taints.push(Taint::Field(
                        self.class_owner_of(parent),
                        self.property_key(&method.key),
                    ));
                }
                AstKind::PropertyDefinition(property) => {
                    taints.push(Taint::Field(
                        self.class_owner_of(parent),
                        self.property_key(&property.key),
                    ));
                }
                AstKind::CallExpression(call)
                    if call
                        .arguments
                        .iter()
                        .any(|argument| argument.span() == span) =>
                {
                    taints.push(Taint::Node(parent));
                }
                AstKind::NewExpression(call)
                    if call
                        .arguments
                        .iter()
                        .any(|argument| argument.span() == span) =>
                {
                    taints.push(Taint::Node(parent));
                }
                _ => {}
            }
            break;
        }
        taints
    }

    /// What a function returning a located value reaches: whatever holds
    /// the function, and, for a function that is itself returned, whatever
    /// holds the function that returns it, since calling that one's result
    /// yields the located value.
    fn returned(&self, function: NodeId, taints: &mut Vec<Taint<'a>>) {
        let mut current = Some(function);
        let mut depth = 0;
        while let Some(function) = current.take()
            && depth < MAX_LOCATION_DEPTH
        {
            taints.extend(self.value_bindings(function));
            // The language runs a getter, a descriptor's `get` or an
            // implicit method whenever its object is used as a whole.
            if let AstKind::ObjectProperty(property) = self.nodes.parent_kind(function)
                && (property.kind != PropertyKind::Init
                    || key_name(&property.key)
                        .is_some_and(|key| key == "get" || IMPLICIT_METHODS.contains(&key)))
            {
                taints.push(Taint::Node(
                    self.nodes.parent_id(self.nodes.parent_id(function)),
                ));
            }
            depth += 1;
            let mut child = function;
            for parent in self.nodes.ancestor_ids(function) {
                match self.nodes.kind(parent) {
                    AstKind::ParenthesizedExpression(_) => child = parent,
                    AstKind::ReturnStatement(_) => {
                        current = self.enclosing_function(parent);
                        break;
                    }
                    AstKind::ArrowFunctionExpression(arrow)
                        if arrow
                            .body
                            .as_expression()
                            .is_some_and(|body| body.span() == self.span(child)) =>
                    {
                        current = Some(parent);
                        break;
                    }
                    _ => break,
                }
            }
        }
    }

    /// Symbols bound or referenced within `span`.
    fn symbols_in(&self, span: Span) -> Vec<Taint<'a>> {
        let first = self
            .identifiers
            .partition_point(|(start, _, _)| *start < span.start);
        self.identifiers[first..]
            .iter()
            .take_while(|(start, _, _)| *start < span.end)
            .filter(|(_, end, _)| *end <= span.end)
            .filter_map(|(_, _, node)| match self.nodes.kind(*node) {
                AstKind::BindingIdentifier(binding) => binding.symbol_id.get(),
                AstKind::IdentifierReference(reference) => self.resolved(reference),
                _ => None,
            })
            .map(Taint::Symbol)
            .collect()
    }

    /// Unresolved `arguments` references inside a function.
    fn arguments_object(&self, function: NodeId) -> Vec<Taint<'a>> {
        let span = self.span(function);
        let first = self
            .identifiers
            .partition_point(|(start, _, _)| *start < span.start);
        self.identifiers[first..]
            .iter()
            .take_while(|(start, _, _)| *start < span.end)
            .filter(|(_, _, node)| {
                matches!(self.nodes.kind(*node), AstKind::IdentifierReference(reference)
                    if reference.name.as_str() == "arguments" && self.resolved(reference).is_none())
            })
            .map(|(_, _, node)| Taint::Node(*node))
            .collect()
    }

    /// What a value stored into `target` reaches: a variable, or a field and
    /// whatever holds its object.
    fn assignment_targets(&self, target: &'a AssignmentTarget<'a>, taints: &mut Vec<Taint<'a>>) {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(identifier)
                if self.resolved(identifier).is_none() =>
            {
                taints.push(Taint::Field(
                    Owner::Global("globalThis", None),
                    Some(identifier.name.as_str()),
                ));
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                taints.push(Taint::Field(
                    self.field_owner(&member.object),
                    self.constant_key(&member.expression),
                ));
                self.container(&member.object, taints);
            }
            target => match expression_target(target) {
                Some((object, name)) => {
                    taints.push(Taint::Field(self.field_owner(object), name));
                    self.container(object, taints);
                }
                None => taints.extend(self.symbols_in(target.span())),
            },
        }
    }

    /// What holds a value stored into `object`: a plain variable, or the
    /// fields an object is itself stored in. A function or class holds its
    /// fields apart from what its calls return, and a global's fields are
    /// tracked one by one.
    fn container(&self, object: &'a Expression<'a>, taints: &mut Vec<Taint<'a>>) {
        let owner = self.store_owner(object);
        if matches!(owner, Owner::Global(..) | Owner::AnyGlobal) {
            return;
        }
        let mut current = inner(object);
        let mut aliases = 0;
        loop {
            current = match current {
                Expression::Identifier(identifier) => {
                    let Some(symbol) = self.resolved(identifier) else {
                        return;
                    };
                    let flags = self.scoping.symbol_flags(symbol);
                    if !(flags.is_function() || flags.is_class()) {
                        taints.push(Taint::Symbol(symbol));
                    }
                    // A parameter's object is its callers' argument.
                    let declaration = self.scoping.symbol_declaration(symbol);
                    if matches!(self.nodes.kind(declaration), AstKind::FormalParameter(_)) {
                        taints.extend(
                            self.parameter_arguments(declaration)
                                .into_iter()
                                .flatten()
                                .flatten()
                                .map(Taint::Holder),
                        );
                    }
                    aliases += 1;
                    match self.alias(symbol) {
                        Some(alias) if aliases <= MAX_LOCATION_DEPTH => alias,
                        _ => return,
                    }
                }
                Expression::ThisExpression(this) => {
                    self.this_holders(this.node_id.get(), taints);
                    return;
                }
                Expression::ComputedMemberExpression(member)
                    if !matches!(member.expression, Expression::StringLiteral(_)) =>
                {
                    taints.push(Taint::Field(owner, None));
                    inner(&member.object)
                }
                expression => match expression_property(expression) {
                    Some((object, name)) => {
                        taints.push(Taint::Field(owner, Some(name)));
                        inner(object)
                    }
                    None => return,
                },
            };
        }
    }

    /// Whether `object` is `process.env`, through `process['env']`, an
    /// alias, a destructuring or an import.
    fn environment_object(&self, object: &'a Expression<'a>) -> bool {
        self.is_environment(object, 0)
    }

    fn is_environment(&self, object: &'a Expression<'a>, depth: usize) -> bool {
        if depth > MAX_LOCATION_DEPTH {
            return false;
        }
        match inner(object) {
            Expression::Identifier(identifier) => {
                let Some(symbol) = self.resolved(identifier) else {
                    return false;
                };
                if let Some(init) = self.initializer(symbol) {
                    return self.is_environment(init, depth + 1);
                }
                let declaration = self.scoping.symbol_declaration(symbol);
                match self.nodes.kind(declaration) {
                    AstKind::VariableDeclarator(declarator) => {
                        declarator
                            .init
                            .as_ref()
                            .is_some_and(|init| self.is_process(init, depth + 1))
                            && self.binding_key(declarator.id.span(), symbol) == Some("env")
                    }
                    AstKind::ImportSpecifier(specifier) => {
                        specifier.imported.name().as_str() == "env"
                            && self.imports_process(declaration)
                    }
                    _ => false,
                }
            }
            expression => expression_property(expression).is_some_and(|(process, name)| {
                name == "env" && self.is_process(process, depth + 1)
            }),
        }
    }

    fn is_process(&self, object: &'a Expression<'a>, depth: usize) -> bool {
        if depth > MAX_LOCATION_DEPTH {
            return false;
        }
        match inner(object) {
            Expression::Identifier(identifier) => match self.resolved(identifier) {
                None => identifier.name.as_str() == "process",
                Some(symbol) => {
                    if let Some(init) = self.initializer(symbol) {
                        return self.is_process(init, depth + 1);
                    }
                    let declaration = self.scoping.symbol_declaration(symbol);
                    matches!(
                        self.nodes.kind(declaration),
                        AstKind::ImportDefaultSpecifier(_) | AstKind::ImportNamespaceSpecifier(_)
                    ) && self.imports_process(declaration)
                }
            },
            Expression::CallExpression(call) => {
                self.is_global(&call.callee, "require")
                    && matches!(call.arguments.first().and_then(Argument::as_expression),
                        Some(Expression::StringLiteral(module))
                            if matches!(module.value.as_str(), "process" | "node:process"))
            }
            expression => expression_property(expression).is_some_and(|(global, name)| {
                name == "process"
                    && ["globalThis", "global", "self", "window"]
                        .iter()
                        .any(|root| self.is_global(global, root))
            }),
        }
    }

    fn imports_process(&self, specifier: NodeId) -> bool {
        matches!(self.nodes.parent_kind(specifier), AstKind::ImportDeclaration(import)
            if matches!(import.source.value.as_str(), "process" | "node:process"))
    }

    /// Whether a name or string draws on a location: a location name, a
    /// location placeholder, or a step environment variable that holds a
    /// location.
    fn names_location(&self, text: &str) -> bool {
        is_location_derived(text)
            || LOCATION_NAMES.iter().any(|name| text.contains(name))
            || self
                .context
                .environment
                .iter()
                .any(|(name, _)| text.contains(name.as_str()))
    }

    fn environment_value(&self, name: &str) -> Option<String> {
        if self.environment_rebound(name) {
            return None;
        }
        if name == "GITHUB_ACTION_PATH" {
            return Some(ACTION_LOCATION.to_string());
        }
        self.context
            .environment
            .iter()
            .find(|(variable, _)| variable == name)
            .map(|(_, value)| value.clone())
    }

    /// The location a member of `import.meta` or `process.env` names.
    fn static_location(&self, object: &'a Expression<'a>, property: &str) -> Option<String> {
        match object.get_inner_expression() {
            Expression::ImportMeta(_) if self.rebound.contains("import.meta") => None,
            Expression::ImportMeta(_) => match property {
                "dirname" => Some(SELF_LOCATION.to_string()),
                "url" | "filename" => Some(format!("{SELF_LOCATION}/{SELF_FILE}")),
                _ => None,
            },
            _ if self.environment_object(object) => self.environment_value(property),
            _ => None,
        }
    }

    /// Whether a node draws on a location directly. Any mention of a
    /// location name counts, whatever it is a property of or bound to, so
    /// that a form this analysis does not evaluate still fails closed.
    fn is_seed(&self, node: NodeId) -> bool {
        match self.nodes.kind(node) {
            AstKind::IdentifierReference(reference) => self.names_location(reference.name.as_str()),
            AstKind::StaticMemberExpression(member) => {
                matches!(
                    member.object.get_inner_expression(),
                    Expression::ImportMeta(_)
                ) || self.names_location(member.property.name.as_str())
            }
            AstKind::ComputedMemberExpression(member) => {
                matches!(
                    member.object.get_inner_expression(),
                    Expression::ImportMeta(_)
                )
            }
            AstKind::PrivateFieldExpression(member) => {
                self.names_location(member.field.name.as_str())
            }
            AstKind::StringLiteral(literal) => self.names_location(literal.value.as_str()),
            AstKind::TemplateLiteral(template) => template.quasis.iter().any(|quasi| {
                self.names_location(
                    quasi
                        .value
                        .cooked
                        .as_ref()
                        .map_or(quasi.value.raw.as_str(), |cooked| cooked.as_str()),
                )
            }),
            AstKind::BindingProperty(property) => {
                key_name(&property.key).is_some_and(|name| self.names_location(name))
            }
            // A module other than a built-in may be one of the action's
            // files, and what it exports may be a location.
            AstKind::CallExpression(call) => {
                self.loads_natively(call)
                    && !matches!(call.arguments.first().and_then(Argument::as_expression).map(inner),
                        Some(Expression::StringLiteral(specifier)) if builtin_module(specifier.value.as_str()))
            }
            _ => false,
        }
    }

    /// The variable a call to `createRequire` imported from `node:module`
    /// binds its loader to, or the call itself when it calls the loader at
    /// once, provided the loader is only ever called: its base then reaches
    /// nothing it loads. Taking the import as Node's own is a heuristic
    /// model the action withdraws by visibly replacing the loader.
    fn native_loader(&self, call: NodeId) -> Option<Option<SymbolId>> {
        let AstKind::CallExpression(factory) = self.nodes.kind(call) else {
            return None;
        };
        if !self.context.native_modules || !self.imports_create_require(&factory.callee) {
            return None;
        }
        let symbol = match self.nodes.parent_kind(call) {
            AstKind::CallExpression(load) if load.callee.span() == factory.span => {
                return Some(None);
            }
            AstKind::VariableDeclarator(declarator) => match &declarator.id {
                BindingPattern::BindingIdentifier(binding) => binding.symbol_id.get()?,
                _ => return None,
            },
            AstKind::AssignmentExpression(assignment) => match &assignment.left {
                AssignmentTarget::AssignmentTargetIdentifier(target) => self.resolved(target)?,
                _ => return None,
            },
            _ => return None,
        };
        let only_called = self
            .scoping
            .get_resolved_references(symbol)
            .all(|reference| {
                let node = reference.node_id();
                reference.is_write()
                    || match self.nodes.parent_kind(node) {
                        AstKind::CallExpression(load) => load.callee.span() == self.span(node),
                        AstKind::BinaryExpression(binary) => binary.operator.is_equality(),
                        AstKind::UnaryExpression(unary) => unary.operator == UnaryOperator::Typeof,
                        _ => false,
                    }
            });
        (only_called
            && self
                .initializer(symbol)
                .is_some_and(|init| init.span() == factory.span))
        .then_some(Some(symbol))
    }

    fn imports_create_require(&self, callee: &'a Expression<'a>) -> bool {
        let Expression::Identifier(identifier) = callee.get_inner_expression() else {
            return false;
        };
        self.resolved(identifier).is_some_and(|symbol| {
            let declaration = self.scoping.symbol_declaration(symbol);
            matches!(self.nodes.kind(declaration), AstKind::ImportSpecifier(specifier)
                if specifier.imported.name().as_str() == "createRequire")
                && matches!(self.nodes.parent_kind(declaration), AstKind::ImportDeclaration(import)
                    if matches!(import.source.value.as_str(), "module" | "node:module"))
        })
    }

    /// Whether a call loads a module through a loader `native_loader`
    /// accepts.
    fn loads_natively(&self, call: &'a CallExpression<'a>) -> bool {
        match call.callee.get_inner_expression() {
            Expression::CallExpression(factory) => {
                self.native_loader(factory.node_id.get()) == Some(None)
            }
            Expression::Identifier(identifier) => self
                .resolved(identifier)
                .and_then(|symbol| self.initializer(symbol))
                .is_some_and(|init| match init.get_inner_expression() {
                    Expression::CallExpression(factory) => self
                        .native_loader(factory.node_id.get())
                        .is_some_and(|loader| loader.is_some()),
                    _ => false,
                }),
            _ => false,
        }
    }

    /// The built-in module, by the root of its name, an expression is: one
    /// Node's loader returned by a literal name, a namespace or default import
    /// of one, or a copy a `LoaderGuard::wrapper` made of one, and whether it
    /// is such a copy.
    fn builtin_module(
        &self,
        expression: &'a Expression<'a>,
        depth: usize,
    ) -> Option<(&'a str, bool)> {
        if !self.context.native_modules || depth > MAX_LOCATION_DEPTH {
            return None;
        }
        match inner(expression) {
            Expression::CallExpression(call) => {
                let module = call.arguments.first().and_then(Argument::as_expression);
                if self.is_global(&call.callee, "require") || self.loads_natively(call) {
                    return module
                        .and_then(literal_text)
                        .filter(|specifier| builtin_module(specifier))
                        .map(|specifier| (builtin_root(specifier), false));
                }
                let (root, _) = self.builtin_module(module?, depth + 1)?;
                self.guard.wrapper(call).then_some((root, true))
            }
            Expression::Identifier(identifier) => {
                let symbol = self.resolved(identifier)?;
                let declaration = self.scoping.symbol_declaration(symbol);
                match (
                    self.nodes.kind(declaration),
                    self.nodes.parent_kind(declaration),
                ) {
                    (
                        AstKind::ImportNamespaceSpecifier(_) | AstKind::ImportDefaultSpecifier(_),
                        AstKind::ImportDeclaration(import),
                    ) => builtin_module(import.source.value.as_str())
                        .then(|| (builtin_root(import.source.value.as_str()), false)),
                    _ => self.builtin_module(self.initializer(symbol)?, depth + 1),
                }
            }
            expression => {
                let (object, name) = expression_property(expression)?;
                if name != "default" {
                    return None;
                }
                self.builtin_module(object, depth + 1)
            }
        }
    }

    /// Whether a method called on `object` is Node's own, under the heuristic
    /// model: the object is a built-in module and no file in the action may
    /// replace that member of it. A wrapper may rename members, so a copy
    /// counts only for a module nothing patches.
    fn native_method(&self, object: &'a Expression<'a>, name: &str) -> bool {
        self.builtin_module(object, 0)
            .is_some_and(|(module, copy)| {
                !self.context.patched_builtins.iter().any(|patch| {
                    patch.split_once(':').is_some_and(|(patched, member)| {
                        patched == module && (copy || member == name || member == "*")
                    })
                })
            })
    }

    /// Propagates location provenance from every seed through the values
    /// that carry it.
    fn trace(&mut self) {
        let mut pending: Vec<NodeId> = self
            .nodes
            .iter()
            .map(|node| node.id())
            .filter(|node| self.is_seed(*node))
            .collect();
        let mut continued = HashSet::new();
        let mut instantiated = HashSet::new();
        let mut holders = HashSet::new();
        let mut taints = Vec::new();
        while let Some(node) = pending.pop() {
            if !self.tainted_nodes.insert(node) {
                continue;
            }
            self.flow(node, &mut continued, &mut taints);
            while let Some(taint) = taints.pop() {
                match taint {
                    Taint::Holder(object) => {
                        let span = object.span();
                        if holders.insert((span.start, span.end)) {
                            self.container(object, &mut taints);
                        }
                    }
                    Taint::Node(node) => pending.push(node),
                    Taint::Symbol(symbol) => {
                        if self.tainted_symbols.insert(symbol) {
                            pending.extend(
                                self.scoping
                                    .get_resolved_references(symbol)
                                    .filter(|reference| reference.is_read())
                                    .map(|reference| reference.node_id()),
                            );
                        }
                    }
                    Taint::Field(owner, name) => {
                        if !self.tainted_fields.insert((owner, name)) {
                            continue;
                        }
                        let (named, unnamed): (Vec<NodeId>, &[NodeId]) = match name {
                            Some(name) => (
                                self.members.get(name).cloned().unwrap_or_default(),
                                &self.unnamed_members,
                            ),
                            // Every field of an unidentified object would be
                            // every field.
                            None if owner == Owner::Unknown => (Vec::new(), &[]),
                            None => (
                                self.members.values().flatten().copied().collect(),
                                &self.unnamed_members,
                            ),
                        };
                        pending.extend(named.into_iter().filter(|read| {
                            self.holds(owner, name.is_some(), self.read_owner(*read))
                        }));
                        pending.extend(
                            unnamed
                                .iter()
                                .copied()
                                .filter(|read| self.holds(owner, false, self.read_owner(*read))),
                        );
                        if matches!(owner, Owner::Global(..) | Owner::AnyGlobal) {
                            pending.extend(self.global_holders(owner));
                        }
                        // An instance carries its class's fields wherever it
                        // goes.
                        // A method that returns a location given one does
                        // not make its instances hold one.
                        if let Owner::Symbol(class) = owner
                            && self.is_class(class)
                            && !name.is_some_and(|name| self.plain_method(owner, name))
                            && instantiated.insert(class)
                        {
                            pending.extend(
                                self.scoping
                                    .get_resolved_references(class)
                                    .map(|reference| reference.node_id())
                                    .filter_map(|node| {
                                        let parent = self.nodes.parent_id(node);
                                        matches!(self.nodes.kind(parent), AstKind::NewExpression(construction)
                                            if construction.callee.span() == self.span(node))
                                        .then_some(parent)
                                    }),
                            );
                        }
                    }
                }
            }
        }
        self.tainted_spans = self
            .tainted_nodes
            .iter()
            .map(|node| {
                let span = self.span(*node);
                (span.start, span.end)
            })
            .collect();
        self.tainted_spans.sort_unstable();
    }

    /// Records what a tainted node's value reaches before its statement
    /// ends. `continued` holds the nodes already followed upward: past one,
    /// every tainted child flows the same way.
    fn flow(&self, node: NodeId, continued: &mut HashSet<NodeId>, taints: &mut Vec<Taint<'a>>) {
        match self.nodes.kind(node) {
            AstKind::BindingProperty(property) => {
                taints.extend(self.symbols_in(property.value.span()));
                return;
            }
            AstKind::AssignmentTargetPropertyIdentifier(property) => {
                taints.extend(self.symbols_in(property.binding.span));
                return;
            }
            AstKind::AssignmentTargetPropertyProperty(property) => {
                taints.extend(self.symbols_in(property.binding.span()));
                return;
            }
            _ => {}
        }
        let mut child = self.span(node);
        for current in self.nodes.ancestor_ids(node) {
            let within = |outer: Span| contains(outer, child);
            let continues = match self.nodes.kind(current) {
                AstKind::VariableDeclarator(declarator) => {
                    if declarator
                        .init
                        .as_ref()
                        .is_some_and(|init| within(init.span()))
                    {
                        taints.extend(self.symbols_in(declarator.id.span()));
                    }
                    false
                }
                AstKind::AssignmentExpression(assignment) => {
                    let right = within(assignment.right.span());
                    if right {
                        self.assignment_targets(&assignment.left, taints);
                    }
                    right
                }
                AstKind::ForOfStatement(statement) => {
                    if within(statement.right.span()) {
                        taints.extend(self.symbols_in(statement.left.span()));
                    }
                    false
                }
                AstKind::ForInStatement(statement) => {
                    if within(statement.right.span()) {
                        taints.extend(self.symbols_in(statement.left.span()));
                    }
                    false
                }
                AstKind::FormalParameter(parameter) => {
                    if parameter
                        .initializer
                        .as_ref()
                        .is_some_and(|initializer| within(initializer.span()))
                    {
                        taints.extend(self.symbols_in(parameter.pattern.span()));
                    }
                    false
                }
                AstKind::AssignmentPattern(pattern) => {
                    if within(pattern.right.span()) {
                        taints.extend(self.symbols_in(pattern.left.span()));
                    }
                    false
                }
                AstKind::AssignmentTargetWithDefault(target) => {
                    if within(target.init.span()) {
                        taints.extend(self.symbols_in(target.binding.span()));
                    }
                    false
                }
                AstKind::AssignmentTargetPropertyIdentifier(property) => {
                    if property
                        .init
                        .as_ref()
                        .is_some_and(|init| within(init.span()))
                    {
                        taints.extend(self.symbols_in(property.binding.span));
                    }
                    false
                }
                // A native loader's base only sets where it resolves from;
                // what it loads draws on a location only as `is_seed` says.
                AstKind::CallExpression(call)
                    if !within(call.callee.span()) && self.native_loader(current).is_some() =>
                {
                    false
                }
                AstKind::CallExpression(call) => {
                    self.call_flow(&call.callee, &call.arguments, child, taints);
                    within(call.callee.span()) || !self.is_known_function(&call.callee)
                }
                // Numbers and booleans are not paths.
                AstKind::BinaryExpression(binary) => binary.operator == BinaryOperator::Addition,
                AstKind::UnaryExpression(_)
                | AstKind::UpdateExpression(_)
                | AstKind::PrivateInExpression(_) => false,
                AstKind::ConditionalExpression(conditional) => !within(conditional.test.span()),
                AstKind::StaticMemberExpression(_)
                | AstKind::ComputedMemberExpression(_)
                | AstKind::PrivateFieldExpression(_) => {
                    let known = self.calls_known_method(current);
                    // Reading a field of a located object runs a getter
                    // defining it on that object with the object as `this`,
                    // and calling a method on it runs the method so.
                    if let Some((object, name)) = self.member_parts_of(current)
                        && within(object.span())
                    {
                        if !known && self.called(current).is_some() {
                            for function in self.member_methods(object, name) {
                                self.this_references(function, taints);
                            }
                        }
                        let owner = self.owner_of(object);
                        let getters: Vec<NodeId> = match name {
                            Some(name) => self
                                .getters
                                .get(&Some(name))
                                .into_iter()
                                .chain(self.getters.get(&None))
                                .flatten()
                                .copied()
                                .collect::<Vec<_>>(),
                            None => self.getters.values().flatten().copied().collect(),
                        }
                        .into_iter()
                        .filter(|(defined, _)| {
                            *defined == Owner::Unknown
                                || *defined == owner
                                    && !matches!(owner, Owner::Unknown | Owner::Receiver)
                        })
                        .map(|(_, getter)| getter)
                        .collect();
                        for getter in getters {
                            self.this_references(getter, taints);
                        }
                    }
                    if known {
                        // The method's `this` is the located receiver.
                        taints.extend(self.receiver_references(current));
                    }
                    !known
                }
                AstKind::NewExpression(call) => {
                    self.call_flow(&call.callee, &call.arguments, child, taints);
                    true
                }
                AstKind::ReturnStatement(_) => {
                    if let Some(function) = self.enclosing_function(current) {
                        self.returned(function, taints);
                    }
                    false
                }
                AstKind::ArrowFunctionExpression(arrow) => {
                    if arrow
                        .body
                        .as_expression()
                        .is_some_and(|body| within(body.span()))
                    {
                        self.returned(current, taints);
                    }
                    false
                }
                AstKind::PropertyDefinition(property) => {
                    if property
                        .value
                        .as_ref()
                        .is_some_and(|value| within(value.span()))
                        && let Some(name) = key_name(&property.key)
                    {
                        taints.push(Taint::Field(self.class_owner_of(current), Some(name)));
                    }
                    false
                }
                AstKind::ExpressionStatement(_)
                | AstKind::IfStatement(_)
                | AstKind::WhileStatement(_)
                | AstKind::DoWhileStatement(_)
                | AstKind::ForStatement(_)
                | AstKind::SwitchStatement(_)
                | AstKind::SwitchCase(_)
                | AstKind::ThrowStatement(_)
                | AstKind::BlockStatement(_)
                | AstKind::TryStatement(_)
                | AstKind::CatchClause(_)
                | AstKind::LabeledStatement(_)
                | AstKind::WithStatement(_)
                | AstKind::VariableDeclaration(_)
                | AstKind::FunctionBody(_)
                | AstKind::Function(_)
                | AstKind::Class(_)
                | AstKind::ClassBody(_)
                | AstKind::MethodDefinition(_)
                | AstKind::StaticBlock(_)
                | AstKind::ExportDefaultDeclaration(_)
                | AstKind::ExportNamedDeclaration(_)
                | AstKind::ImportExpression(_)
                | AstKind::Program(_) => false,
                _ => true,
            };
            if !continues || !continued.insert(current) {
                break;
            }
            child = self.span(current);
        }
    }

    /// What a tainted callee, receiver or argument reaches through a call.
    fn call_flow(
        &self,
        callee: &'a Expression<'a>,
        arguments: &'a [Argument<'a>],
        child: Span,
        taints: &mut Vec<Taint<'a>>,
    ) {
        // A function this file does not define may hand what it is given,
        // or a value derived from its located receiver, to its callbacks,
        // as arguments or as what they are called on.
        if contains(callee.span(), child) || !self.is_known_function(callee) {
            for argument in arguments {
                for function in self.callback_functions(argument) {
                    if let Some(params) = self.parameters(function) {
                        taints.extend(self.symbols_in(params.span));
                    }
                    self.this_references(function, taints);
                }
            }
        }
        if contains(callee.span(), child) {
            return;
        }
        let index = arguments.partition_point(|argument| argument.span().end <= child.start);
        if !arguments
            .get(index)
            .is_some_and(|argument| contains(argument.span(), child))
        {
            return;
        }
        let mut any_parameter = matches!(arguments[index], Argument::SpreadElement(_));
        let mut functions: Vec<NodeId> = Vec::new();
        match inner(callee) {
            Expression::Identifier(identifier) => {
                if let Some(symbol) = self.resolved(identifier) {
                    functions.extend(self.callee_functions(symbol));
                    // A parameter called with a location may be the callback
                    // that settles the call its function was passed to.
                    let declaration = self.scoping.symbol_declaration(symbol);
                    if matches!(self.nodes.kind(declaration), AstKind::FormalParameter(_))
                        && let Some(function) = self.enclosing_function(declaration)
                    {
                        taints.extend(
                            self.value_bindings(function)
                                .into_iter()
                                .filter(|taint| matches!(taint, Taint::Node(_))),
                        );
                    }
                }
            }
            Expression::FunctionExpression(function) => functions.push(function.node_id.get()),
            Expression::ArrowFunctionExpression(function) => {
                functions.push(function.node_id.get());
            }
            expression => {
                if let Some((object, name)) = expression_property(expression) {
                    if matches!(name, "call" | "apply" | "bind") {
                        any_parameter = true;
                        for function in self.held_functions(object) {
                            // Its first argument is what it is called on.
                            self.this_references(function, taints);
                            functions.push(function);
                        }
                    } else if self.native_method(object, name) {
                        // Node's own methods, under the heuristic model: no
                        // function this file defines is one.
                    } else {
                        let owner = self.store_owner(object);
                        functions.extend(
                            self.methods
                                .get(name)
                                .into_iter()
                                .flatten()
                                .filter(|(method_owner, _)| {
                                    owner == Owner::Unknown
                                        || *method_owner == owner
                                        || *method_owner == Owner::Unknown
                                })
                                .map(|(_, function)| *function),
                        );
                        if MUTATING_METHODS.contains(&name) {
                            self.container(object, taints);
                        }
                        if STORING_FUNCTIONS.contains(&name)
                            && index > 0
                            && let Some(target) =
                                arguments.first().and_then(Argument::as_expression)
                        {
                            taints.push(Taint::Field(self.store_owner(target), None));
                            self.container(target, taints);
                        }
                    }
                }
            }
        }
        for function in functions {
            let Some(params) = self.parameters(function) else {
                continue;
            };
            if any_parameter {
                taints.extend(self.symbols_in(params.span));
            } else if let Some(parameter) = params.items.get(index) {
                taints.extend(self.symbols_in(parameter.pattern.span()));
            } else if let Some(rest) = &params.rest {
                taints.extend(self.symbols_in(rest.span));
            }
            taints.extend(self.arguments_object(function));
        }
    }

    /// Whether a callee is a function in this file, whose result carries a
    /// location only through what it returns.
    fn is_known_function(&self, callee: &'a Expression<'a>) -> bool {
        match inner(callee) {
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => true,
            Expression::Identifier(identifier) => self.resolved(identifier).is_some_and(|symbol| {
                !self.is_written(symbol)
                    && self
                        .functions
                        .get(&symbol)
                        .is_some_and(|functions| !functions.is_empty())
            }),
            // A method of a class or object in this file, unless something
            // else may have been stored under its name.
            callee => expression_property(callee).is_some_and(|(object, name)| {
                let owner = self.owner_of(object);
                matches!(owner, Owner::Symbol(_) | Owner::Node(_))
                    && self
                        .methods
                        .get(name)
                        .is_some_and(|methods| methods.iter().any(|(method, _)| *method == owner))
                    && [owner, Owner::Unknown].iter().all(|owner| {
                        !self.redefined.contains(&(*owner, Some(name)))
                            && !self.redefined.contains(&(*owner, None))
                    })
                    && !self
                        .stores
                        .get(name)
                        .into_iter()
                        .flatten()
                        .any(|(store, value)| {
                            (*store == owner || *store == Owner::Unknown)
                                && !value.is_some_and(|value| {
                                    matches!(
                                        inner(value),
                                        Expression::FunctionExpression(_)
                                            | Expression::ArrowFunctionExpression(_)
                                    )
                                })
                        })
            }),
        }
    }

    /// Whether a member expression is a call of a method this file defines,
    /// which returns a location only through what it returns, whatever its
    /// receiver holds.
    fn calls_known_method(&self, member: NodeId) -> bool {
        let span = self.span(member);
        let mut callee = member;
        for parent in self.nodes.ancestor_ids(member) {
            match self.nodes.kind(parent) {
                AstKind::ParenthesizedExpression(_) => callee = parent,
                AstKind::CallExpression(call) if call.callee.span() == self.span(callee) => {
                    return inner(&call.callee).span() == span
                        && self.is_known_function(&call.callee);
                }
                _ => return false,
            }
        }
        false
    }

    /// Whether a field is only ever an ordinary method, which runs only
    /// when called by name.
    fn plain_method(&self, owner: Owner<'a>, name: &str) -> bool {
        let methods: Vec<NodeId> = self
            .methods
            .get(name)
            .into_iter()
            .flatten()
            .filter(|(method, _)| *method == owner)
            .map(|(_, function)| *function)
            .collect();
        !IMPLICIT_METHODS.contains(&name)
            && !methods.is_empty()
            && methods
                .iter()
                .all(|function| !self.accessors.contains(function))
    }

    /// The `this` references of the methods a known method call reaches.
    fn receiver_references(&self, member: NodeId) -> Vec<Taint<'a>> {
        let Some((object, name)) = member_property(self.nodes.kind(member)) else {
            return Vec::new();
        };
        let owner = self.owner_of(object);
        let functions: Vec<NodeId> = self
            .methods
            .get(name)
            .into_iter()
            .flatten()
            .filter(|(method, _)| *method == owner || *method == Owner::Unknown)
            .map(|(_, function)| *function)
            .collect();
        let mut taints = Vec::new();
        for function in functions {
            self.this_references(function, &mut taints);
        }
        taints
    }

    /// The `this` references of a function's own body.
    fn this_references(&self, function: NodeId, taints: &mut Vec<Taint<'a>>) {
        if !matches!(self.nodes.kind(function), AstKind::Function(_)) {
            return;
        }
        let span = self.span(function);
        let first = self
            .receivers
            .partition_point(|(start, _)| *start < span.start);
        for (start, this) in &self.receivers[first..] {
            if *start >= span.end {
                break;
            }
            // `this` belongs to the nearest function that is not an arrow.
            if self
                .nodes
                .ancestor_ids(*this)
                .find(|ancestor| matches!(self.nodes.kind(*ancestor), AstKind::Function(_)))
                == Some(function)
            {
                taints.push(Taint::Node(*this));
            }
        }
    }

    /// The field an object literal describes, when it is a property
    /// descriptor: an argument of a `defineProperty` call, a value of an
    /// argument of a `defineProperties` or `create` call, or a variable
    /// passed as one. `Some(None)` is a descriptor of a field this analysis
    /// cannot name.
    fn described(&self, literal: NodeId) -> Option<(Owner<'a>, Option<&'a str>)> {
        let mut current = literal;
        let mut key = None;
        for _ in 0..=MAX_LOCATION_DEPTH {
            let parent = self.nodes.parent_id(current);
            match self.nodes.kind(parent) {
                AstKind::ParenthesizedExpression(_) => current = parent,
                AstKind::ObjectProperty(property) if key.is_none() => {
                    key = Some(self.property_key(&property.key));
                    current = self.nodes.parent_id(parent);
                }
                AstKind::CallExpression(call) => return self.describes(call, current, key),
                AstKind::VariableDeclarator(declarator) => {
                    let BindingPattern::BindingIdentifier(binding) = &declarator.id else {
                        return None;
                    };
                    let symbol = binding.symbol_id.get()?;
                    let fields: Vec<(Owner<'a>, Option<&'a str>)> = self
                        .scoping
                        .get_resolved_references(symbol)
                        .filter_map(|reference| {
                            let node = reference.node_id();
                            match self.nodes.parent_kind(node) {
                                AstKind::CallExpression(call) => self.describes(call, node, key),
                                _ => None,
                            }
                        })
                        .collect();
                    return match fields.as_slice() {
                        [] => None,
                        [field] => Some(*field),
                        _ => Some((Owner::Unknown, None)),
                    };
                }
                _ => return None,
            }
        }
        None
    }

    /// The object and field `call` describes with `argument`, when it is a
    /// descriptor of one, or a map of them whose value `key` names. What
    /// `create` makes has no owner this analysis can name.
    fn describes(
        &self,
        call: &'a CallExpression<'a>,
        argument: NodeId,
        key: Option<Option<&'a str>>,
    ) -> Option<(Owner<'a>, Option<&'a str>)> {
        let span = self.span(argument);
        let index = call
            .arguments
            .iter()
            .position(|argument| argument.span() == span)?;
        let target = || {
            call.arguments
                .first()
                .and_then(Argument::as_expression)
                .map_or(Owner::Unknown, |target| self.store_owner(target))
        };
        match (expression_property(inner(&call.callee))?.1, key) {
            ("defineProperty", None) if index == 2 => Some((
                target(),
                call.arguments
                    .get(1)
                    .and_then(Argument::as_expression)
                    .and_then(|name| self.constant_key(name)),
            )),
            ("defineProperties", Some(name)) if index == 1 => Some((target(), name)),
            ("create", Some(name)) if index == 1 => Some((Owner::Unknown, name)),
            _ => None,
        }
    }

    /// The call whose callee is `node`, through parentheses.
    fn called(&self, node: NodeId) -> Option<&'a CallExpression<'a>> {
        let mut callee = node;
        for parent in self.nodes.ancestor_ids(node) {
            match self.nodes.kind(parent) {
                AstKind::ParenthesizedExpression(_) => callee = parent,
                AstKind::CallExpression(call) if call.callee.span() == self.span(callee) => {
                    return Some(call);
                }
                _ => return None,
            }
        }
        None
    }

    /// The functions an expression may hold: an inline function, one bound
    /// to a variable, or a method stored under the field it names.
    fn held_functions(&self, expression: &'a Expression<'a>) -> Vec<NodeId> {
        match inner(expression) {
            Expression::FunctionExpression(function) => vec![function.node_id.get()],
            Expression::ArrowFunctionExpression(function) => vec![function.node_id.get()],
            Expression::Identifier(identifier) => self
                .resolved(identifier)
                .map(|symbol| self.callee_functions(symbol))
                .unwrap_or_default(),
            expression => match self.member_parts(expression) {
                Some((object, Some(name))) => self.member_methods(object, Some(name)),
                _ => Vec::new(),
            },
        }
    }

    /// The methods a field read from `object` may hold: those stored on
    /// that object, or through one this analysis cannot identify, under
    /// the field's name or any name.
    fn member_methods(&self, object: &'a Expression<'a>, name: Option<&str>) -> Vec<NodeId> {
        let owner = self.owner_of(object);
        let methods: Vec<&(Owner<'a>, NodeId)> = match name {
            Some(name) => self.methods.get(name).into_iter().flatten().collect(),
            None => self.methods.values().flatten().collect(),
        };
        methods
            .into_iter()
            .filter(|(method, _)| {
                *method == Owner::Unknown
                    || *method == owner && !matches!(owner, Owner::Unknown | Owner::Receiver)
            })
            .map(|(_, function)| *function)
            .collect()
    }

    /// What holds a value stored into `this` at `node`: the object literal
    /// whose method it is, and whatever its function is called on,
    /// constructed as, or bound or applied to. A class's instances carry
    /// its fields already.
    fn this_holders(&self, node: NodeId, taints: &mut Vec<Taint<'a>>) {
        match self.this_owner(node) {
            Owner::Symbol(symbol) if !self.is_class(symbol) => taints.push(Taint::Symbol(symbol)),
            Owner::Node(value)
                if matches!(self.nodes.kind(value), AstKind::ObjectExpression(_)) =>
            {
                taints.push(Taint::Node(value));
            }
            _ => {}
        }
        let Some(function) = self
            .nodes
            .ancestor_ids(node)
            .find(|ancestor| matches!(self.nodes.kind(*ancestor), AstKind::Function(_)))
        else {
            return;
        };
        for binding in self.value_bindings(function) {
            match binding {
                Taint::Symbol(symbol) => {
                    for reference in self.scoping.get_resolved_references(symbol) {
                        self.bound_receivers(reference.node_id(), taints);
                    }
                }
                Taint::Field(_, name) => {
                    let members = match name {
                        Some(name) => self.members.get(name).cloned().unwrap_or_default(),
                        None => self.unnamed_members.clone(),
                    };
                    for member in members {
                        if self.called(member).is_some()
                            && let Some((object, _)) = self.member_parts_of(member)
                        {
                            taints.push(Taint::Holder(object));
                        }
                        self.bound_receivers(member, taints);
                    }
                }
                Taint::Node(call) => self.bound_receivers_of(call, function, taints),
                Taint::Holder(_) => {}
            }
        }
    }

    /// The receivers a function at `node` is given: the instance `new`
    /// creates, or the arguments of a call it is passed to, or bound or
    /// applied through.
    fn bound_receivers(&self, node: NodeId, taints: &mut Vec<Taint<'a>>) {
        let parent = self.nodes.parent_id(node);
        match self.nodes.kind(parent) {
            AstKind::NewExpression(construction)
                if construction.callee.span() == self.span(node) =>
            {
                taints.push(Taint::Node(parent));
            }
            AstKind::CallExpression(_) => self.bound_receivers_of(parent, node, taints),
            AstKind::StaticMemberExpression(_) | AstKind::ComputedMemberExpression(_)
                if self
                    .member_parts_of(parent)
                    .is_some_and(|(object, _)| object.span() == self.span(node)) =>
            {
                if let Some(call) = self.called(parent) {
                    taints.extend(
                        call.arguments
                            .iter()
                            .filter_map(Argument::as_expression)
                            .map(Taint::Holder),
                    );
                }
            }
            _ => {}
        }
    }

    /// The other arguments of a call a function is passed to, any of which
    /// may be what it is called on.
    fn bound_receivers_of(&self, call: NodeId, function: NodeId, taints: &mut Vec<Taint<'a>>) {
        let AstKind::CallExpression(call) = self.nodes.kind(call) else {
            return;
        };
        let span = self.span(function);
        if !call
            .arguments
            .iter()
            .any(|argument| contains(argument.span(), span))
        {
            return;
        }
        taints.extend(
            call.arguments
                .iter()
                .filter(|argument| !contains(argument.span(), span))
                .filter_map(Argument::as_expression)
                .map(Taint::Holder),
        );
    }

    /// The object and field of a member expression node.
    fn member_parts_of(&self, member: NodeId) -> Option<(&'a Expression<'a>, Option<&'a str>)> {
        match self.nodes.kind(member) {
            AstKind::StaticMemberExpression(member) => {
                Some((&member.object, Some(member.property.name.as_str())))
            }
            AstKind::ComputedMemberExpression(member) => {
                Some((&member.object, self.constant_key(&member.expression)))
            }
            AstKind::PrivateFieldExpression(member) => {
                Some((&member.object, Some(member.field.name.as_str())))
            }
            _ => None,
        }
    }

    /// A callee's receiver and the name its function is known by: an
    /// imported or destructured function's original name, or its own.
    fn callee_name(
        &self,
        callee: &'a Expression<'a>,
    ) -> Option<(Option<&'a Expression<'a>>, &'a str)> {
        match inner(callee) {
            Expression::Identifier(identifier) => {
                let original = self.resolved(identifier).and_then(|symbol| {
                    let declaration = self.scoping.symbol_declaration(symbol);
                    match self.nodes.kind(declaration) {
                        AstKind::ImportSpecifier(specifier) => {
                            Some(specifier.imported.name().as_str())
                        }
                        AstKind::VariableDeclarator(declarator)
                            if !matches!(declarator.id, BindingPattern::BindingIdentifier(_)) =>
                        {
                            self.binding_key(declarator.id.span(), symbol)
                        }
                        _ => None,
                    }
                });
                Some((None, original.unwrap_or(identifier.name.as_str())))
            }
            callee => expression_property(callee).map(|(object, name)| (Some(object), name)),
        }
    }

    /// The functions a variable calls: those bound to it, or to a variable
    /// it aliases.
    fn callee_functions(&self, symbol: SymbolId) -> Vec<NodeId> {
        let mut functions = Vec::new();
        let mut current = Some(symbol);
        let mut depth = 0;
        while let Some(symbol) = current.take()
            && depth < MAX_LOCATION_DEPTH
        {
            functions.extend(self.functions.get(&symbol).into_iter().flatten());
            depth += 1;
            match self.initializer(symbol).map(inner) {
                Some(Expression::Identifier(alias)) => current = self.resolved(alias),
                Some(member) => {
                    if let Some((object, Some(name))) = self.member_parts(member) {
                        functions.extend(self.member_methods(object, Some(name)));
                    }
                }
                None => {}
            }
        }
        functions
    }

    /// The functions an argument passes as a callback: inline, by name, or
    /// as a method stored under the field it reads.
    fn callback_functions(&self, argument: &'a Argument<'a>) -> Vec<NodeId> {
        argument
            .as_expression()
            .map(|expression| self.held_functions(expression))
            .unwrap_or_default()
    }

    fn parameters(&self, function: NodeId) -> Option<&'a FormalParameters<'a>> {
        match self.nodes.kind(function) {
            AstKind::Function(function) => Some(&function.params),
            AstKind::ArrowFunctionExpression(function) => Some(&function.params),
            _ => None,
        }
    }

    fn enclosing_function(&self, node: NodeId) -> Option<NodeId> {
        self.nodes.ancestor_ids(node).find(|ancestor| {
            matches!(
                self.nodes.kind(*ancestor),
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
            )
        })
    }

    /// Whether any tainted node lies within `span`.
    fn is_tainted(&self, span: Span) -> bool {
        let first = self
            .tainted_spans
            .partition_point(|(start, _)| *start < span.start);
        self.tainted_spans[first..]
            .iter()
            .take_while(|(start, _)| *start < span.end)
            .any(|(_, end)| *end <= span.end)
    }

    fn opaque(&self, span: Span) -> String {
        if self.is_tainted(span) {
            UNRESOLVED_LOCATION.to_string()
        } else {
            DYNAMIC_VALUE.to_string()
        }
    }

    fn is_written(&self, symbol: SymbolId) -> bool {
        self.scoping
            .get_resolved_references(symbol)
            .any(|reference| reference.is_write())
    }

    /// Whether a value may change through a field write or a storing call,
    /// so that its initializer does not describe it.
    fn is_mutated(&self, symbol: SymbolId) -> bool {
        self.scoping.get_resolved_references(symbol).any(|reference| {
            let node = reference.node_id();
            let parent = self.nodes.parent_id(node);
            match self.nodes.kind(parent) {
                AstKind::CallExpression(call) => {
                    call.arguments
                        .first()
                        .is_some_and(|argument| argument.span() == self.span(node))
                        && expression_property(inner(&call.callee))
                            .is_some_and(|(_, name)| STORING_FUNCTIONS.contains(&name))
                }
                AstKind::StaticMemberExpression(_)
                | AstKind::ComputedMemberExpression(_)
                | AstKind::PrivateFieldExpression(_) => {
                    let name = member_property(self.nodes.kind(parent)).map(|(_, name)| name);
                    self.store_of(parent).is_some()
                        || matches!(self.nodes.parent_kind(parent), AstKind::CallExpression(call)
                            if call.callee.span() == self.span(parent)
                                && name.is_some_and(|name| MUTATING_METHODS.contains(&name)))
                }
                _ => false,
            }
        })
    }

    /// The initializer of a variable declared alone and never reassigned.
    fn initializer(&self, symbol: SymbolId) -> Option<&'a Expression<'a>> {
        let AstKind::VariableDeclarator(declarator) =
            self.nodes.kind(self.scoping.symbol_declaration(symbol))
        else {
            return None;
        };
        if !matches!(declarator.id, BindingPattern::BindingIdentifier(_)) {
            return None;
        }
        let mut writes = self
            .scoping
            .get_resolved_references(symbol)
            .filter(|reference| reference.is_write());
        match (&declarator.init, writes.next(), writes.next()) {
            (Some(init), None, _) => Some(init),
            // `var x; ... x = value;`, as bundlers initialize modules lazily.
            (None, Some(write), None) => match self.nodes.parent_kind(write.node_id()) {
                AstKind::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign
                        && assignment.left.span() == self.span(write.node_id()) =>
                {
                    Some(&assignment.right)
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// The value of a symbol with one plain initialization; otherwise only
    /// its provenance.
    fn value_of(&self, symbol: SymbolId, depth: usize) -> String {
        if let Some(cached) = self.values.borrow().get(&symbol) {
            return cached.clone();
        }
        self.values
            .borrow_mut()
            .insert(symbol, DYNAMIC_VALUE.to_string());
        let declaration = self.scoping.symbol_declaration(symbol);
        let value = if let Some(init) = self.initializer(symbol) {
            self.evaluate(init, depth + 1)
        } else if self.is_written(symbol) {
            DYNAMIC_VALUE.to_string()
        } else {
            match self.nodes.kind(declaration) {
                AstKind::VariableDeclarator(declarator) => match &declarator.init {
                    Some(init) if self.environment_object(init) => self
                        .binding_key(declarator.id.span(), symbol)
                        .and_then(|name| self.environment_value(name))
                        .unwrap_or_else(|| DYNAMIC_VALUE.to_string()),
                    // A loop variable takes each element of what it iterates.
                    None => match self.nodes.parent_kind(self.nodes.parent_id(declaration)) {
                        AstKind::ForOfStatement(statement)
                            if matches!(declarator.id, BindingPattern::BindingIdentifier(_)) =>
                        {
                            merge_location_values(self.evaluate_words(&statement.right, depth + 1))
                        }
                        _ => DYNAMIC_VALUE.to_string(),
                    },
                    _ => DYNAMIC_VALUE.to_string(),
                },
                AstKind::FormalParameter(_) => self
                    .parameter_value(declaration, depth)
                    .unwrap_or_else(|| DYNAMIC_VALUE.to_string()),
                _ => DYNAMIC_VALUE.to_string(),
            }
        };
        let value = if !is_location_derived(&value) && self.tainted_symbols.contains(&symbol) {
            UNRESOLVED_LOCATION.to_string()
        } else {
            value
        };
        self.values.borrow_mut().insert(symbol, value.clone());
        value
    }

    /// The value a parameter takes at every call of its function, when the
    /// function is only ever called directly and so has no other callers.
    fn parameter_value(&self, parameter: NodeId, depth: usize) -> Option<String> {
        let AstKind::FormalParameter(formal) = self.nodes.kind(parameter) else {
            return None;
        };
        let values: Vec<String> = self
            .parameter_arguments(parameter)?
            .into_iter()
            .map(
                |argument| match argument.or(formal.initializer.as_deref()) {
                    Some(argument) => self.evaluate(argument, depth + 1),
                    None => DYNAMIC_VALUE.to_string(),
                },
            )
            .collect();
        Some(merge_location_values(values))
    }

    /// What a parameter receives at every call of its function, when the
    /// function is only ever called directly; `None` where a call leaves
    /// the argument out.
    fn parameter_arguments(&self, parameter: NodeId) -> Option<Vec<Option<&'a Expression<'a>>>> {
        if let Some(cached) = self.arguments.borrow().get(&parameter) {
            return cached.clone();
        }
        let arguments = self.find_parameter_arguments(parameter);
        self.arguments
            .borrow_mut()
            .insert(parameter, arguments.clone());
        arguments
    }

    fn find_parameter_arguments(
        &self,
        parameter: NodeId,
    ) -> Option<Vec<Option<&'a Expression<'a>>>> {
        let AstKind::FormalParameter(formal) = self.nodes.kind(parameter) else {
            return None;
        };
        if !matches!(formal.pattern, BindingPattern::BindingIdentifier(_)) {
            return None;
        }
        let list = self.nodes.parent_id(parameter);
        let AstKind::FormalParameters(params) = self.nodes.kind(list) else {
            return None;
        };
        let index = params
            .items
            .iter()
            .position(|item| item.span == formal.span)?;
        let function = self.nodes.parent_id(list);
        // An exported function has callers outside this file.
        for kind in self.nodes.ancestor_kinds(function) {
            match kind {
                AstKind::ExportNamedDeclaration(_) | AstKind::ExportDefaultDeclaration(_) => {
                    return None;
                }
                AstKind::VariableDeclarator(_)
                | AstKind::VariableDeclaration(_)
                | AstKind::ParenthesizedExpression(_) => {}
                _ => break,
            }
        }
        let mut calls: Vec<&'a CallExpression<'a>> = Vec::new();
        let mut callee = function;
        for parent in self.nodes.ancestor_ids(function) {
            match self.nodes.kind(parent) {
                AstKind::ParenthesizedExpression(_) => callee = parent,
                AstKind::CallExpression(call) if call.callee.span() == self.span(callee) => {
                    calls.push(call);
                    break;
                }
                _ => break,
            }
        }
        for binding in self.value_bindings(function) {
            let Taint::Symbol(symbol) = binding else {
                return None;
            };
            if self.is_written(symbol) {
                return None;
            }
            for reference in self.scoping.get_resolved_references(symbol) {
                let node = reference.node_id();
                match self.nodes.parent_kind(node) {
                    AstKind::CallExpression(call) if call.callee.span() == self.span(node) => {
                        calls.push(call);
                    }
                    _ => return None,
                }
            }
        }
        if calls.is_empty() {
            return None;
        }
        calls
            .into_iter()
            .map(|call| {
                if call.arguments[..call.arguments.len().min(index + 1)]
                    .iter()
                    .any(|argument| matches!(argument, Argument::SpreadElement(_)))
                {
                    None
                } else {
                    Some(call.arguments.get(index).and_then(Argument::as_expression))
                }
            })
            .collect()
    }

    /// The key an object pattern within `span` binds `symbol` from.
    fn binding_key(&self, span: Span, symbol: SymbolId) -> Option<&'a str> {
        let first = self
            .identifiers
            .partition_point(|(start, _, _)| *start < span.start);
        self.identifiers[first..]
            .iter()
            .take_while(|(start, _, _)| *start < span.end)
            .find_map(|(_, _, node)| match self.nodes.kind(*node) {
                AstKind::BindingIdentifier(binding) if binding.symbol_id.get() == Some(symbol) => {
                    match self.nodes.parent_kind(*node) {
                        AstKind::BindingProperty(property) => key_name(&property.key),
                        _ => None,
                    }
                }
                _ => None,
            })
    }

    /// The value every plain store into a field gives it. An object this
    /// analysis cannot identify may also be a literal defining the field.
    fn field_value(&self, owner: Owner<'a>, name: &'a str, span: Span, depth: usize) -> String {
        if matches!(owner, Owner::Unknown | Owner::Receiver) && self.literal_names.contains(name) {
            return self.opaque(span);
        }
        if let Some(cached) = self.field_values.borrow().get(&(owner, name)) {
            return cached.clone();
        }
        self.field_values
            .borrow_mut()
            .insert((owner, name), UNRESOLVED_LOCATION.to_string());
        let stores: Vec<&Store<'a>> = self
            .stores
            .get(name)
            .into_iter()
            .flatten()
            .filter(|(store_owner, _)| self.holds(*store_owner, true, owner))
            .collect();
        let value = if stores.is_empty() || stores.iter().any(|(_, value)| value.is_none()) {
            self.opaque(span)
        } else {
            merge_location_values(
                stores
                    .iter()
                    .filter_map(|(_, value)| *value)
                    .map(|value| self.evaluate(value, depth + 1))
                    .collect::<Vec<_>>(),
            )
        };
        let value = if is_location_derived(&value) {
            value
        } else {
            UNRESOLVED_LOCATION.to_string()
        };
        self.field_values
            .borrow_mut()
            .insert((owner, name), value.clone());
        value
    }

    /// The object literal an expression is, directly or through a variable
    /// that never changes.
    fn object_literal(&self, expression: &'a Expression<'a>) -> Option<&'a ObjectExpression<'a>> {
        match inner(expression) {
            Expression::ObjectExpression(object) => Some(object),
            Expression::Identifier(identifier) => {
                let symbol = self.resolved(identifier)?;
                if self.is_mutated(symbol) {
                    return None;
                }
                match inner(self.initializer(symbol)?) {
                    Expression::ObjectExpression(object) => Some(object),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn is_array(&self, expression: &'a Expression<'a>) -> bool {
        match inner(expression) {
            Expression::ArrayExpression(_) => true,
            Expression::Identifier(identifier) => self
                .resolved(identifier)
                .and_then(|symbol| self.initializer(symbol))
                .is_some_and(|init| matches!(inner(init), Expression::ArrayExpression(_))),
            _ => false,
        }
    }

    fn evaluate(&self, expression: &'a Expression<'a>, depth: usize) -> String {
        let value = if depth > MAX_LOCATION_DEPTH {
            self.opaque(expression.span())
        } else {
            self.evaluate_form(expression, depth)
        };
        let located = is_location_derived(&value);
        if located && value.len() <= MAX_LOCATION_VALUE_BYTES {
            value
        } else if located || self.is_tainted(expression.span()) {
            // Whatever its form, an expression that draws on a location
            // keeps that provenance.
            UNRESOLVED_LOCATION.to_string()
        } else if value.len() > MAX_LOCATION_VALUE_BYTES {
            DYNAMIC_VALUE.to_string()
        } else {
            value
        }
    }

    fn evaluate_form(&self, expression: &'a Expression<'a>, depth: usize) -> String {
        let span = expression.span();
        match inner(expression) {
            Expression::StringLiteral(literal) => literal.value.to_string(),
            Expression::TemplateLiteral(template) => {
                let mut value = String::new();
                for (index, quasi) in template.quasis.iter().enumerate() {
                    value.push_str(
                        quasi
                            .value
                            .cooked
                            .as_ref()
                            .map_or(quasi.value.raw.as_str(), |cooked| cooked.as_str()),
                    );
                    if let Some(part) = template.expressions.get(index) {
                        value.push_str(&self.evaluate(part, depth + 1));
                    }
                    if value.len() > MAX_LOCATION_VALUE_BYTES {
                        break;
                    }
                }
                value
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                let mut value = self.evaluate(&binary.left, depth + 1);
                if value.len() <= MAX_LOCATION_VALUE_BYTES {
                    value.push_str(&self.evaluate(&binary.right, depth + 1));
                }
                value
            }
            Expression::LogicalExpression(logical) => merge_location_values([
                self.evaluate(&logical.left, depth + 1),
                self.evaluate(&logical.right, depth + 1),
            ]),
            Expression::ConditionalExpression(conditional) => merge_location_values([
                self.evaluate(&conditional.consequent, depth + 1),
                self.evaluate(&conditional.alternate, depth + 1),
            ]),
            Expression::Identifier(identifier) => match self.resolved(identifier) {
                Some(symbol) => self.value_of(symbol, depth),
                None => match identifier.name.as_str() {
                    name if self.rebound.contains(name) => self.opaque(span),
                    "__dirname" => SELF_LOCATION.to_string(),
                    "__filename" => format!("{SELF_LOCATION}/{SELF_FILE}"),
                    _ => DYNAMIC_VALUE.to_string(),
                },
            },
            Expression::CallExpression(call) => self.evaluate_call(call, depth),
            Expression::NewExpression(call) if self.is_global(&call.callee, "URL") => {
                let values = self.evaluate_arguments(&call.arguments, depth);
                let relative = values.first().cloned().unwrap_or_default();
                match values.get(1) {
                    Some(base) if !relative.starts_with('/') && !is_location_derived(&relative) => {
                        let directory = if base.ends_with(SELF_FILE) {
                            dirname_location(base)
                        } else {
                            base.clone()
                        };
                        join_location([directory, relative], true)
                    }
                    _ => relative,
                }
            }
            expression => {
                let Some((object, name)) = expression_property(expression) else {
                    return self.opaque(span);
                };
                if let Some(location) = self.static_location(object, name) {
                    return location;
                }
                if name == "execPath" && self.is_global(object, "process") {
                    return "node".to_string();
                }
                if matches!(name, "href" | "pathname") {
                    return self.evaluate(object, depth + 1);
                }
                if let Some(literal) = self.object_literal(object) {
                    return match self.literal_property(literal, name) {
                        Some(value) => self.evaluate(value, depth + 1),
                        None => self.opaque(span),
                    };
                }
                let owner = self.owner_of(object);
                if self.field_tainted(owner, name) {
                    return self.field_value(owner, name, span, depth);
                }
                self.opaque(span)
            }
        }
    }

    /// The value an object literal's last definition of `name` gives it,
    /// unless a spread, computed key or accessor may be the definition.
    fn literal_property(
        &self,
        literal: &'a ObjectExpression<'a>,
        name: &str,
    ) -> Option<&'a Expression<'a>> {
        for property in literal.properties.iter().rev() {
            let ObjectPropertyKind::ObjectProperty(property) = property else {
                return None;
            };
            match key_name(&property.key) {
                Some(key) if key == name => {
                    return (property.kind == PropertyKind::Init && !property.method)
                        .then_some(&property.value);
                }
                Some(_)
                    if !property.computed
                        || matches!(property.key, PropertyKey::StringLiteral(_)) => {}
                _ => return None,
            }
        }
        None
    }

    fn evaluate_arguments(&self, arguments: &'a [Argument<'a>], depth: usize) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| match argument.as_expression() {
                Some(expression) => self.evaluate(expression, depth + 1),
                None => self.opaque(argument.span()),
            })
            .collect()
    }

    fn evaluate_call(&self, call: &'a CallExpression<'a>, depth: usize) -> String {
        let span = call.span;
        let Some((receiver, function)) = self.callee_name(&call.callee) else {
            return self.opaque(span);
        };
        if let Some(receiver) = receiver
            && matches!(receiver.get_inner_expression(), Expression::ImportMeta(_))
        {
            if function != "resolve" {
                return self.opaque(span);
            }
            let relative = self.evaluate_arguments(&call.arguments, depth);
            return join_location(
                std::iter::once(SELF_LOCATION.to_string()).chain(relative),
                true,
            );
        }
        let located_receiver = receiver
            .map(|receiver| self.evaluate(receiver, depth + 1))
            .filter(|value| is_location_derived(value));
        let arguments = || self.evaluate_arguments(&call.arguments, depth);
        match (function, receiver) {
            ("join", Some(receiver)) if self.is_array(receiver) => {
                let separator = arguments()
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| ",".to_string());
                if is_location_derived(&separator) {
                    return UNRESOLVED_LOCATION.to_string();
                }
                self.evaluate_words(receiver, depth + 1).join(&separator)
            }
            // Node's `path.join` appends an absolute-looking part; `resolve`
            // restarts at one.
            ("join", _) if located_receiver.is_none() => join_location(arguments(), false),
            ("resolve", _) if located_receiver.is_none() => join_location(arguments(), true),
            ("dirname", _) => dirname_location(
                &located_receiver
                    .or_else(|| arguments().into_iter().next())
                    .unwrap_or_else(|| DYNAMIC_VALUE.to_string()),
            ),
            ("normalize" | "fileURLToPath" | "realpathSync" | "String" | "toString", _) => {
                match located_receiver {
                    Some(receiver) => receiver,
                    None => join_location(arguments(), true),
                }
            }
            ("concat", _) if located_receiver.is_some() => {
                let mut value = located_receiver.unwrap_or_default();
                for argument in arguments() {
                    value.push_str(&argument);
                }
                value
            }
            ("basename" | "extname" | "relative", _) => DYNAMIC_VALUE.to_string(),
            _ => self.opaque(span),
        }
    }

    /// The words of an argument vector.
    fn evaluate_words(&self, expression: &'a Expression<'a>, depth: usize) -> Vec<String> {
        let words = if depth > MAX_LOCATION_DEPTH {
            vec![self.opaque(expression.span())]
        } else {
            self.evaluate_word_form(expression, depth)
        };
        if words.len() <= MAX_LOCATION_WORDS {
            words
        } else {
            vec![self.opaque(expression.span())]
        }
    }

    fn evaluate_word_form(&self, expression: &'a Expression<'a>, depth: usize) -> Vec<String> {
        match inner(expression) {
            Expression::ArrayExpression(array) => {
                let mut words = Vec::new();
                for element in &array.elements {
                    match element {
                        ArrayExpressionElement::SpreadElement(spread) => {
                            words.extend(self.evaluate_words(&spread.argument, depth + 1));
                        }
                        ArrayExpressionElement::Elision(_) => {}
                        element => {
                            if let Some(expression) = element.as_expression() {
                                words.push(self.evaluate(expression, depth + 1));
                            }
                        }
                    }
                    if words.len() > MAX_LOCATION_WORDS {
                        break;
                    }
                }
                words
            }
            Expression::Identifier(identifier) => {
                let Some(symbol) = self.resolved(identifier) else {
                    return vec![self.opaque(expression.span())];
                };
                if let Some(words) = self.words.borrow().get(&symbol) {
                    return words.clone();
                }
                self.words
                    .borrow_mut()
                    .insert(symbol, vec![self.opaque(expression.span())]);
                let words = match self.initializer(symbol) {
                    Some(init) if !self.is_mutated(symbol) => self.evaluate_words(init, depth + 1),
                    _ => vec![self.value_of(symbol, depth + 1)],
                };
                self.words.borrow_mut().insert(symbol, words.clone());
                words
            }
            _ => vec![self.evaluate(expression, depth + 1)],
        }
    }

    /// The `cwd` an options argument sets, or `None` when it sets none.
    fn options_directory(&self, argument: &'a Expression<'a>) -> Option<LocatedDirectory> {
        if self.is_array(argument) {
            return None;
        }
        let Some(object) = self.object_literal(argument) else {
            return self
                .is_tainted(argument.span())
                .then_some(LocatedDirectory::Unresolved);
        };
        for property in object.properties.iter().rev() {
            match property {
                ObjectPropertyKind::ObjectProperty(property) => match key_name(&property.key) {
                    Some("cwd") => {
                        return Some(LocatedDirectory::from_value(
                            &self.evaluate(&property.value, 0),
                        ));
                    }
                    Some(_) => {}
                    None if self.is_tainted(property.span) => {
                        return Some(LocatedDirectory::Unresolved);
                    }
                    None => {}
                },
                ObjectPropertyKind::SpreadProperty(spread) => {
                    if self.is_tainted(spread.span) {
                        return Some(LocatedDirectory::Unresolved);
                    }
                }
            }
        }
        None
    }

    /// Whether the receiver of an `exec` method is proven to be a regular
    /// expression whose `exec` is the native method: a literal, or a
    /// variable holding only one that nothing can reach to replace the
    /// method, in a file that does not expose `RegExp` itself.
    fn is_regex(&self, receiver: &'a Expression<'a>) -> bool {
        if self.regexp_exposed {
            return false;
        }
        match inner(receiver) {
            Expression::RegExpLiteral(_) => true,
            Expression::Identifier(identifier) => self.resolved(identifier).is_some_and(|symbol| {
                self.initializer(symbol)
                    .is_some_and(|init| self.creates_regex(init))
                    && self.regex_confined(symbol)
            }),
            _ => false,
        }
    }

    fn creates_regex(&self, expression: &'a Expression<'a>) -> bool {
        match inner(expression) {
            Expression::RegExpLiteral(_) => true,
            Expression::NewExpression(call) => self.is_global(&call.callee, "RegExp"),
            Expression::CallExpression(call) => self.is_global(&call.callee, "RegExp"),
            _ => false,
        }
    }

    /// Whether every use of a variable holding a regular expression only
    /// reads it: calls its methods, reads a property other than its
    /// prototype, resets `lastIndex`, or hands it to a string method.
    fn regex_confined(&self, symbol: SymbolId) -> bool {
        self.scoping
            .get_resolved_references(symbol)
            .all(|reference| {
                if reference.is_write() {
                    // The one assignment `initializer` accepted.
                    return true;
                }
                let node = reference.node_id();
                let span = self.span(node);
                let parent = self.nodes.parent_id(node);
                match self.nodes.kind(parent) {
                    AstKind::StaticMemberExpression(_) | AstKind::ComputedMemberExpression(_) => {
                        member_property(self.nodes.kind(parent)).is_some_and(|(_, name)| {
                            REGEX_PROPERTIES.contains(&name)
                                && (self.store_of(parent).is_none() || name == "lastIndex")
                        })
                    }
                    // Only a string method, never a method this file defines
                    // under the same name.
                    AstKind::CallExpression(call) => {
                        call.callee.span() != span
                            && expression_property(inner(&call.callee)).is_some_and(|(_, name)| {
                                REGEX_CONSUMERS.contains(&name) && !self.defines(name)
                            })
                    }
                    AstKind::BinaryExpression(_) | AstKind::UnaryExpression(_) => true,
                    _ => false,
                }
            })
    }

    /// Whether the file can reach `RegExp` or a regular expression's
    /// prototype other than by constructing, calling or testing against it,
    /// so that `RegExp.prototype.exec` may have been replaced. A regular
    /// expression handed to other code is not followed there.
    fn exposes_regexp(&self) -> bool {
        self.nodes.iter().any(|node| {
            let id = node.id();
            match node.kind() {
                // Evaluated code can do anything.
                AstKind::IdentifierReference(reference)
                    if matches!(reference.name.as_str(), "eval" | "Function")
                        && self.resolved(reference).is_none() =>
                {
                    true
                }
                AstKind::IdentifierReference(reference) => {
                    reference.name.as_str() == "RegExp"
                        && self.resolved(reference).is_none()
                        && !match self.nodes.parent_kind(id) {
                            AstKind::NewExpression(call) => call.callee.span() == reference.span,
                            AstKind::CallExpression(call) => call.callee.span() == reference.span,
                            AstKind::BinaryExpression(binary) => {
                                binary.operator == BinaryOperator::Instanceof
                                    && binary.right.span() == reference.span
                            }
                            _ => false,
                        }
                }
                AstKind::StaticMemberExpression(member) => {
                    member.property.name.as_str() == "RegExp"
                        || matches!(
                            member.property.name.as_str(),
                            "__proto__" | "constructor" | "__defineGetter__" | "__defineSetter__"
                        ) && self.is_regex_value(&member.object)
                }
                AstKind::ComputedMemberExpression(member) => {
                    match self.constant_key(&member.expression) {
                        Some(key) => {
                            key == "RegExp"
                                || matches!(key, "__proto__" | "constructor")
                                    && self.is_regex_value(&member.object)
                        }
                        // An unknown global may be `RegExp`.
                        None => {
                            self.is_regex_value(&member.object)
                                || self.owner_of(&member.object) == Owner::Global("globalThis", None)
                        }
                    }
                }
                AstKind::BindingProperty(property) => {
                    self.property_key(&property.key) == Some("RegExp")
                        || property.computed && self.unknown_global_key(id, &property.key)
                }
                AstKind::AssignmentTargetPropertyIdentifier(property) => {
                    property.binding.name.as_str() == "RegExp"
                }
                AstKind::AssignmentTargetPropertyProperty(property) => {
                    self.property_key(&property.name) == Some("RegExp")
                        || property.computed && self.unknown_global_key(id, &property.name)
                }
                AstKind::StringLiteral(literal) => {
                    literal.value.as_str() == "RegExp"
                        && matches!(self.nodes.parent_kind(id), AstKind::CallExpression(_))
                }
                AstKind::CallExpression(call) => {
                    let Some((_, name)) = expression_property(inner(&call.callee)) else {
                        return false;
                    };
                    let Some(target) = call.arguments.first().and_then(Argument::as_expression)
                    else {
                        return false;
                    };
                    match name {
                        // Adding data fields leaves `exec` alone.
                        "assign" => {
                            self.is_regex_value(target)
                                && !call.arguments.iter().skip(1).all(|source| {
                                    source
                                        .as_expression()
                                        .and_then(|source| self.object_literal(source))
                                        .is_some_and(|literal| {
                                            literal.properties.iter().all(|property| {
                                                matches!(property,
                                                    ObjectPropertyKind::ObjectProperty(property)
                                                        if !property.computed
                                                            && key_name(&property.key).is_some_and(|key| {
                                                                !matches!(key, "exec" | "__proto__" | "constructor")
                                                            }))
                                            })
                                        })
                                })
                        }
                        "getPrototypeOf" | "setPrototypeOf" | "defineProperty"
                        | "defineProperties" | "set" => self.is_regex_value(target),
                        _ => false,
                    }
                }
                _ => false,
            }
        })
    }

    /// Whether a destructured property reads a global under a key that may
    /// be any name, as a computed member of the global object does.
    fn unknown_global_key(&self, property: NodeId, key: &'a PropertyKey<'a>) -> bool {
        self.property_key(key).is_none()
            && matches!(
                self.read_owner(property),
                Owner::Global("globalThis", None) | Owner::AnyGlobal
            )
    }

    /// Whether an expression is a regular expression: constructed there, or
    /// held by a variable initialized with one.
    fn is_regex_value(&self, expression: &'a Expression<'a>) -> bool {
        self.creates_regex(expression)
            || matches!(inner(expression), Expression::Identifier(identifier)
                if self
                    .resolved(identifier)
                    .and_then(|symbol| self.initializer(symbol))
                    .is_some_and(|init| self.creates_regex(init)))
    }

    fn executions(&self) -> Vec<LocatedExecution> {
        let mut directories: Vec<(u32, LocatedDirectory)> = Vec::new();
        for node in self.nodes.iter() {
            if let AstKind::CallExpression(call) = node.kind()
                && let Some((object, "chdir")) = expression_property(inner(&call.callee))
                && self.is_global(object, "process")
            {
                let directory = match call.arguments.first().and_then(Argument::as_expression) {
                    Some(argument) => LocatedDirectory::from_value(&self.evaluate(argument, 0)),
                    None => LocatedDirectory::Unresolved,
                };
                directories.push((call.span.start, directory));
            }
        }
        directories.sort_by_key(|(start, _)| *start);
        let mut executions = Vec::new();
        for node in self.nodes.iter() {
            let (span, callee, arguments, constructor) = match node.kind() {
                AstKind::CallExpression(call) => (call.span, &call.callee, &call.arguments, false),
                AstKind::NewExpression(call) => (call.span, &call.callee, &call.arguments, true),
                _ => continue,
            };
            let Some((receiver, name)) = self.callee_name(callee) else {
                continue;
            };
            let runs = if constructor {
                name == "Worker"
            } else {
                EXECUTION_CALLS.contains(&name)
            };
            if !runs || name == "exec" && receiver.is_some_and(|receiver| self.is_regex(receiver)) {
                continue;
            }
            let default_directory = directories
                .iter()
                .rev()
                .find(|(start, _)| *start < span.start)
                .map_or_else(
                    || self.context.directory.clone(),
                    |(_, directory)| directory.clone(),
                );
            if default_directory == LocatedDirectory::Caller
                && !arguments
                    .iter()
                    .any(|argument| self.is_tainted(argument.span()))
            {
                continue;
            }
            self.record_execution(name, arguments, default_directory, &mut executions);
        }
        executions
    }

    /// Whether an options argument may choose a located program, shell,
    /// interpreter, environment or input: any located option other than
    /// those that cannot.
    fn selects_program(&self, argument: &'a Expression<'a>) -> bool {
        if matches!(
            inner(argument),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            return false;
        }
        let Some(object) = self.object_literal(argument) else {
            return self.is_tainted(argument.span());
        };
        object.properties.iter().any(|property| match property {
            ObjectPropertyKind::ObjectProperty(property) => {
                !key_name(&property.key).is_some_and(|key| INERT_OPTIONS.contains(&key))
                    && self.is_tainted(property.span)
            }
            ObjectPropertyKind::SpreadProperty(spread) => self.is_tainted(spread.span),
        })
    }

    fn record_execution(
        &self,
        name: &str,
        arguments: &'a [Argument<'a>],
        default_directory: LocatedDirectory,
        executions: &mut Vec<LocatedExecution>,
    ) {
        let Some(first) = arguments.first().and_then(Argument::as_expression) else {
            executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
            return;
        };
        let mut rest = Vec::new();
        for argument in arguments.iter().skip(1) {
            match argument.as_expression() {
                Some(expression) => rest.push(expression),
                None if self.is_tainted(argument.span()) => {
                    executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
                    return;
                }
                None => {}
            }
        }
        let extra = rest.first().copied().filter(|argument| {
            matches!(inner(argument), Expression::ArrayExpression(_))
                || matches!(inner(argument), Expression::Identifier(_))
                    && self.object_literal(argument).is_none()
        });
        // A variable in the arguments' place may hold options instead, as
        // Node accepts either there; only an array is certainly arguments.
        let options: Vec<&'a Expression<'a>> = rest
            .iter()
            .copied()
            .filter(|argument| !self.is_array(argument))
            .collect();
        if options
            .iter()
            .any(|argument| self.selects_program(argument))
        {
            executions.push(LocatedExecution::unresolved(SourceFileKind::Shell));
        }
        let directory = options
            .iter()
            .find_map(|argument| self.options_directory(argument))
            .unwrap_or(default_directory);
        let program = self.evaluate(first, 0);
        let extra = extra.map(|argument| self.evaluate_words(argument, 0));
        let command_string = matches!(
            name,
            "exec" | "execSync" | "getExecOutput" | "execaCommand" | "execaCommandSync"
        ) || program.contains(char::is_whitespace);
        let scan = ShellScan {
            depth: 0,
            composite: false,
        };
        match (name, extra) {
            ("fork" | "Worker" | "execaNode", _) => command_located_executions(
                &["node".to_string(), program],
                &directory,
                scan,
                executions,
            ),
            (_, None) if command_string => shell_script_executions(
                &program,
                false,
                scan,
                ShellLocationState::starting_in(directory),
                executions,
            ),
            (_, extra) => {
                let mut words = if command_string {
                    shell_words(&program)
                } else {
                    vec![program]
                };
                words.extend(extra.unwrap_or_default());
                command_located_executions(&words, &directory, scan, executions);
            }
        }
    }
}

/// The object and field an assignment target writes, when it is a member;
/// a computed key without a static name writes any field.
fn expression_target<'a>(
    target: &'a AssignmentTarget<'a>,
) -> Option<(&'a Expression<'a>, Option<&'a str>)> {
    match target {
        AssignmentTarget::StaticMemberExpression(member) => {
            Some((&member.object, Some(member.property.name.as_str())))
        }
        AssignmentTarget::PrivateFieldExpression(member) => {
            Some((&member.object, Some(member.field.name.as_str())))
        }
        AssignmentTarget::ComputedMemberExpression(member) => Some((
            &member.object,
            match &member.expression {
                Expression::StringLiteral(key) => Some(key.value.as_str()),
                _ => None,
            },
        )),
        _ => None,
    }
}
