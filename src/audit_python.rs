//! Syntax boundaries for Python location analysis. Parsing runs out of process
//! because source files are untrusted and nesting can exhaust the parser stack.

use ruff_python_ast::visitor::{Visitor, walk_expr, walk_stmt};
use ruff_python_ast::{Expr, Stmt};
use ruff_text_size::Ranged;
use serde::{Deserialize, Serialize};

pub(crate) const WORKER_ARGUMENT: &str = "--python-location-worker";
const WORKER_STACK_BYTES: usize = 256 << 20;
const WORKER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Scope {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) body_start: usize,
    pub(crate) parent: usize,
    pub(crate) name: Option<String>,
    pub(crate) class_name: Option<String>,
    pub(crate) parameters: Vec<String>,
    pub(crate) default_location: bool,
    pub(crate) decorated: bool,
    pub(crate) located_names: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Call {
    pub(crate) scope: usize,
    pub(crate) callee_start: usize,
    pub(crate) callee_end: usize,
    pub(crate) arguments: Vec<(usize, usize)>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Shape {
    pub(crate) scopes: Vec<Scope>,
    pub(crate) calls: Vec<Call>,
    pub(crate) returns: Vec<(usize, usize, usize)>,
    pub(crate) other_bindings: Vec<(usize, String, usize)>,
    pub(crate) location_return: bool,
    pub(crate) location_global: bool,
    pub(crate) location_comprehension: bool,
    pub(crate) located_fields: Vec<String>,
}

impl Shape {
    pub(crate) fn unscoped(length: usize) -> Self {
        Self {
            scopes: vec![Scope {
                start: 0,
                end: length,
                body_start: 0,
                parent: 0,
                name: None,
                class_name: None,
                parameters: Vec::new(),
                default_location: false,
                decorated: false,
                located_names: Vec::new(),
            }],
            calls: Vec::new(),
            returns: Vec::new(),
            other_bindings: Vec::new(),
            location_return: false,
            location_global: false,
            location_comprehension: false,
            located_fields: Vec::new(),
        }
    }

    pub(crate) fn inside_header(&self, position: usize) -> bool {
        self.scopes
            .iter()
            .skip(1)
            .any(|scope| position >= scope.start && position < scope.body_start)
    }

    pub(crate) fn scope_at(&self, position: usize) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .rev()
            .find(|(_, scope)| position >= scope.body_start && position < scope.end)
            .map_or(0, |(index, _)| index)
    }

    pub(crate) fn is_ancestor(&self, ancestor: usize, mut scope: usize) -> bool {
        loop {
            if scope == ancestor {
                return true;
            }
            if scope == 0 {
                return false;
            }
            scope = self.scopes[scope].parent;
        }
    }

    pub(crate) fn defines_function(&self, name: &str, scope: usize, position: usize) -> bool {
        self.function(name, scope, position).is_some()
    }

    pub(crate) fn function(
        &self,
        name: &str,
        scope: usize,
        position: usize,
    ) -> Option<(usize, &Scope)> {
        self.scopes.iter().enumerate().rev().find(|(_, function)| {
            function.name.as_deref() == Some(name)
                && function.start < position
                && self.is_ancestor(function.parent, scope)
                && !self
                    .other_bindings
                    .iter()
                    .any(|(binding_scope, binding_name, binding_at)| {
                        *binding_scope == function.parent
                            && binding_name == name
                            && *binding_at > function.start
                            && *binding_at < position
                    })
        })
    }

    pub(crate) fn function_may_execute(&self, index: usize, code: &str) -> bool {
        let function = &self.scopes[index];
        function.decorated
            || self.calls.iter().any(|call| {
                if !self.is_ancestor(index, call.scope) {
                    return false;
                }
                let callee = &code[call.callee_start..call.callee_end];
                crate::audit_source::python_execution_name(callee)
                    || function.parameters.iter().any(|name| name == callee)
                    || !self.call_is_inert(callee)
            })
    }

    pub(crate) fn call_is_inert(&self, callee: &str) -> bool {
        match callee {
            "print" | "str" | "len" | "Path" | "open" => {
                !self.scopes.iter().any(|scope| {
                    scope.name.as_deref() == Some(callee)
                        || scope.parameters.iter().any(|parameter| parameter == callee)
                }) && !self
                    .other_bindings
                    .iter()
                    .any(|(_, name, _)| name == callee)
            }
            "pathlib.Path" | "os.path.join" | "os.path.dirname" | "os.path.abspath"
            | "os.path.realpath" | "os.path.normpath" | "os.path.exists" | "os.chdir" => true,
            _ => false,
        }
    }

    pub(crate) fn argument_has_path(&self, mut scope: usize, identifiers: &[&str]) -> bool {
        let mut pending: std::collections::HashSet<&str> = identifiers.iter().copied().collect();
        loop {
            let lexical = &self.scopes[scope];
            if lexical.class_name.is_none() || scope == 0 {
                if lexical
                    .located_names
                    .iter()
                    .any(|name| pending.contains(name.as_str()))
                {
                    return true;
                }
                for parameter in &lexical.parameters {
                    pending.remove(parameter.as_str());
                }
            }
            if scope == 0 || pending.is_empty() {
                return false;
            }
            scope = lexical.parent;
        }
    }
}

struct Collector<'a> {
    code: &'a str,
    shape: Shape,
    stack: Vec<usize>,
    location_names: Vec<Vec<String>>,
    global_names: Vec<Vec<String>>,
}

impl Collector<'_> {
    fn target_names(target: &Expr, names: &mut Vec<String>) {
        match target {
            Expr::Name(name) => names.push(name.id.to_string()),
            Expr::Tuple(tuple) => {
                for element in &tuple.elts {
                    Self::target_names(element, names);
                }
            }
            Expr::List(list) => {
                for element in &list.elts {
                    Self::target_names(element, names);
                }
            }
            Expr::Starred(starred) => Self::target_names(&starred.value, names),
            _ => {}
        }
    }

    fn located_comprehension(
        &self,
        generators: &[ruff_python_ast::Comprehension],
        body: &str,
    ) -> bool {
        if !super::audit_source::python_contains_execution_call(body) {
            return false;
        }
        if super::audit_source::python_mentions_location(body) {
            return true;
        }
        generators.iter().any(|generator| {
            if !self.value_is_located(&generator.iter) {
                return false;
            }
            let mut targets = Vec::new();
            Self::target_names(&generator.target, &mut targets);
            body.split(|character: char| !(character.is_alphanumeric() || character == '_'))
                .any(|part| targets.iter().any(|name| name == part))
        })
    }

    fn value_is_located(&self, value: &Expr) -> bool {
        let range = value.range();
        let expression = &self.code[usize::from(range.start())..usize::from(range.end())];
        if super::audit_source::python_mentions_location(expression) {
            return true;
        }
        let carries_path = match value {
            Expr::Call(call) => {
                let callee = call.func.range();
                let name = &self.code[usize::from(callee.start())..usize::from(callee.end())];
                let terminal = name.rsplit('.').next().unwrap_or(name);
                !matches!(
                    name,
                    "json.load"
                        | "json.loads"
                        | "os.path.exists"
                        | "os.path.isfile"
                        | "os.path.isdir"
                        | "os.path.islink"
                        | "os.path.getsize"
                ) && !matches!(
                    terminal,
                    "read" | "readline" | "readlines" | "read_text" | "read_bytes"
                )
            }
            _ => true,
        };
        if !carries_path {
            return false;
        }
        let mut pending: std::collections::HashSet<&str> = expression
            .split(|character: char| !(character.is_alphanumeric() || character == '_'))
            .collect();
        for level in (0..self.stack.len()).rev() {
            let scope = &self.shape.scopes[self.stack[level]];
            if (level == self.stack.len() - 1 || scope.class_name.is_none())
                && self.location_names[level]
                    .iter()
                    .any(|name| pending.contains(name.as_str()))
            {
                return true;
            }
            for parameter in &scope.parameters {
                pending.remove(parameter.as_str());
            }
        }
        false
    }

    fn record_located_target(&mut self, target: &Expr) {
        match target {
            Expr::Name(name) => {
                self.shape.location_global |= self
                    .global_names
                    .last()
                    .unwrap()
                    .iter()
                    .any(|global| global == name.id.as_str());
                if self.shape.scopes[*self.stack.last().unwrap()]
                    .class_name
                    .is_some()
                {
                    self.shape.located_fields.push(name.id.to_string());
                }
                self.location_names
                    .last_mut()
                    .unwrap()
                    .push(name.id.to_string());
            }
            Expr::Attribute(attribute) => {
                self.shape.located_fields.push(attribute.attr.to_string());
                self.record_located_holder(&attribute.value);
            }
            Expr::Subscript(subscript) => self.record_located_holder(&subscript.value),
            _ => {}
        }
    }

    fn record_located_holder(&mut self, holder: &Expr) {
        if let Expr::Name(name) = holder {
            self.location_names
                .last_mut()
                .unwrap()
                .push(name.id.to_string());
        }
    }

    fn record_target_binding(&mut self, target: &Expr, at: usize) {
        match target {
            Expr::Name(name) => self.shape.other_bindings.push((
                *self.stack.last().unwrap_or(&0),
                name.id.to_string(),
                at,
            )),
            Expr::Tuple(tuple) => {
                for element in &tuple.elts {
                    self.record_target_binding(element, at);
                }
            }
            Expr::List(list) => {
                for element in &list.elts {
                    self.record_target_binding(element, at);
                }
            }
            Expr::Starred(starred) => self.record_target_binding(&starred.value, at),
            _ => {}
        }
    }
}

impl<'a> Visitor<'a> for Collector<'_> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(function) => {
                let body_start = function
                    .body
                    .first()
                    .map_or(usize::from(function.range.end()), |stmt| {
                        usize::from(stmt.range().start())
                    });
                let mut parameters: Vec<String> = function
                    .parameters
                    .iter()
                    .map(|parameter| parameter.name().to_string())
                    .collect();
                parameters.sort_unstable();
                let default_location =
                    function
                        .parameters
                        .iter_non_variadic_params()
                        .any(|parameter| {
                            parameter.default().is_some_and(|default| {
                                let range = default.range();
                                super::audit_source::python_mentions_location(
                                    &self.code
                                        [usize::from(range.start())..usize::from(range.end())],
                                )
                            })
                        });
                let index = self.shape.scopes.len();
                self.shape.scopes.push(Scope {
                    start: usize::from(function.range.start()),
                    end: usize::from(function.range.end()),
                    body_start,
                    parent: *self.stack.last().unwrap_or(&0),
                    name: Some(function.name.to_string()),
                    class_name: None,
                    parameters,
                    default_location,
                    decorated: !function.decorator_list.is_empty(),
                    located_names: Vec::new(),
                });
                self.stack.push(index);
                self.location_names.push(Vec::new());
                self.global_names.push(Vec::new());
                for stmt in &function.body {
                    self.visit_stmt(stmt);
                }
                self.stack.pop();
                self.shape.scopes[index].located_names = self.location_names.pop().unwrap();
                self.global_names.pop();
            }
            Stmt::ClassDef(class) => {
                let body_start = class
                    .body
                    .first()
                    .map_or(usize::from(class.range.end()), |stmt| {
                        usize::from(stmt.range().start())
                    });
                let index = self.shape.scopes.len();
                self.shape.scopes.push(Scope {
                    start: usize::from(class.range.start()),
                    end: usize::from(class.range.end()),
                    body_start,
                    parent: *self.stack.last().unwrap_or(&0),
                    name: None,
                    class_name: Some(class.name.to_string()),
                    parameters: Vec::new(),
                    default_location: false,
                    decorated: false,
                    located_names: Vec::new(),
                });
                self.stack.push(index);
                self.location_names.push(Vec::new());
                self.global_names.push(Vec::new());
                for stmt in &class.body {
                    self.visit_stmt(stmt);
                }
                self.stack.pop();
                self.shape.scopes[index].located_names = self.location_names.pop().unwrap();
                self.global_names.pop();
            }
            Stmt::Global(statement) => {
                self.global_names
                    .last_mut()
                    .unwrap()
                    .extend(statement.names.iter().map(ToString::to_string));
            }
            Stmt::Import(statement) => {
                for alias in &statement.names {
                    let name = alias.asname.as_ref().unwrap_or(&alias.name);
                    self.shape.other_bindings.push((
                        *self.stack.last().unwrap(),
                        name.to_string(),
                        usize::from(statement.range.start()),
                    ));
                }
            }
            Stmt::ImportFrom(statement) => {
                for alias in &statement.names {
                    let name = alias.asname.as_ref().unwrap_or(&alias.name);
                    self.shape.other_bindings.push((
                        *self.stack.last().unwrap(),
                        name.to_string(),
                        usize::from(statement.range.start()),
                    ));
                }
            }
            Stmt::Assign(assignment) => {
                let located = self.value_is_located(&assignment.value);
                if located {
                    for target in &assignment.targets {
                        self.record_located_target(target);
                    }
                }
                for target in &assignment.targets {
                    self.record_target_binding(target, usize::from(assignment.range.start()));
                }
                walk_stmt(self, stmt);
            }
            Stmt::AnnAssign(assignment) => {
                if assignment
                    .value
                    .as_ref()
                    .is_some_and(|value| self.value_is_located(value))
                {
                    self.record_located_target(&assignment.target);
                }
                self.record_target_binding(
                    &assignment.target,
                    usize::from(assignment.range.start()),
                );
                walk_stmt(self, stmt);
            }
            Stmt::AugAssign(assignment) => {
                self.record_target_binding(
                    &assignment.target,
                    usize::from(assignment.range.start()),
                );
                walk_stmt(self, stmt);
            }
            Stmt::For(loop_stmt) => {
                self.record_target_binding(&loop_stmt.target, usize::from(loop_stmt.range.start()));
                walk_stmt(self, stmt);
            }
            Stmt::With(with_stmt) => {
                for item in &with_stmt.items {
                    if let Some(target) = &item.optional_vars {
                        self.record_target_binding(target, usize::from(item.range.start()));
                    }
                }
                walk_stmt(self, stmt);
            }
            Stmt::Return(statement) => {
                if let Some(value) = &statement.value {
                    let range = value.range();
                    self.shape.returns.push((
                        *self.stack.last().unwrap(),
                        usize::from(range.start()),
                        usize::from(range.end()),
                    ));
                    let expression =
                        &self.code[usize::from(range.start())..usize::from(range.end())];
                    self.shape.location_return |=
                        super::audit_source::python_mentions_location(expression)
                            || self
                                .location_names
                                .last()
                                .unwrap()
                                .iter()
                                .any(|name| name == expression);
                }
                walk_stmt(self, stmt);
            }
            _ => walk_stmt(self, stmt),
        }
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Named(named) = expr {
            self.record_target_binding(&named.target, usize::from(named.range.start()));
        }
        let comprehension = match expr {
            Expr::ListComp(comprehension) => {
                Some((&comprehension.generators[..], comprehension.elt.range()))
            }
            Expr::SetComp(comprehension) => {
                Some((&comprehension.generators[..], comprehension.elt.range()))
            }
            Expr::Generator(comprehension) => {
                Some((&comprehension.generators[..], comprehension.elt.range()))
            }
            _ => None,
        };
        if let Some((generators, body)) = comprehension {
            let source = &self.code[usize::from(body.start())..usize::from(body.end())];
            self.shape.location_comprehension |= self.located_comprehension(generators, source);
        }
        if let Expr::Call(call) = expr {
            let range = call.func.range();
            let arguments = call
                .arguments
                .args
                .iter()
                .map(|argument| argument.range())
                .chain(
                    call.arguments
                        .keywords
                        .iter()
                        .map(|keyword| keyword.value.range()),
                )
                .map(|range| (usize::from(range.start()), usize::from(range.end())))
                .collect();
            self.shape.calls.push(Call {
                scope: *self.stack.last().unwrap_or(&0),
                callee_start: usize::from(range.start()),
                callee_end: usize::from(range.end()),
                arguments,
            });
        }
        walk_expr(self, expr);
    }
}

fn parse(code: &str) -> Option<Shape> {
    let parsed = ruff_python_parser::parse_module(code).ok()?;
    if !parsed.has_no_syntax_errors() {
        return None;
    }
    let mut collector = Collector {
        code,
        shape: Shape::unscoped(code.len()),
        stack: vec![0],
        location_names: vec![Vec::new()],
        global_names: vec![Vec::new()],
    };
    for stmt in &parsed.syntax().body {
        collector.visit_stmt(stmt);
    }
    collector.shape.scopes[0].located_names = collector.location_names.pop().unwrap();
    Some(collector.shape)
}

pub(crate) fn shape(code: &str) -> Option<Shape> {
    if cfg!(test) {
        return parse(code);
    }
    in_worker(code)
}

fn in_worker(code: &str) -> Option<Shape> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

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
    let source = code.as_bytes().to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&source));
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

pub(crate) fn run_worker() -> std::process::ExitCode {
    use std::io::{Read, Write};
    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        return std::process::ExitCode::FAILURE;
    }
    let Ok(code) = String::from_utf8(input) else {
        return std::process::ExitCode::FAILURE;
    };
    let analysis = std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || parse(&code).and_then(|shape| serde_json::to_vec(&shape).ok()));
    let Ok(Ok(Some(answer))) = analysis.map(std::thread::JoinHandle::join) else {
        return std::process::ExitCode::FAILURE;
    };
    if std::io::stdout().lock().write_all(&answer).is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
