#!/usr/bin/env python3
"""
SG Reconstructor — converts VLD opcode dumps (from PHP 8.3 + SG loader)
back into readable PHP source code.

Parses the fixed-width column format that VLD outputs.

Usage:
    python3 sg_reconstructor_advanced.py <dump.txt> [-o output.php]
    python3 sg_reconstructor_advanced.py --batch /tmp/sg_dumps/ -o /tmp/recovered/
"""

import re
import sys
import argparse
from urllib.parse import unquote_plus
from pathlib import Path
from typing import List, Dict, Optional, Tuple


def decode_str(s: str) -> str:
    return unquote_plus(s)


def decode_ns(name: str) -> str:
    return decode_str(name)


# ---------------------------------------------------------------------------
# Dump parser — fixed-width column format
# ---------------------------------------------------------------------------

# VLD header:
# line      #* E I O op                               fetch          ext  return  operands
# The 'operands' column starts at a consistent position after the 'return' column.
# We detect the header positions dynamically.

class OpLine:
    __slots__ = ("idx", "opcode", "ext_val", "ret", "operands_raw", "is_dead")

    def __init__(self, idx, opcode, ext_val, ret, operands_raw, is_dead=False):
        self.idx = idx
        self.opcode = opcode
        self.ext_val = ext_val
        self.ret = ret
        self.operands_raw = operands_raw
        self.is_dead = is_dead


class FuncDump:
    def __init__(self, name: str, class_name: str = ""):
        self.name = name
        self.class_name = class_name
        self.ops: List[OpLine] = []
        self.compiled_vars: Dict[str, str] = {}


class ClassDump:
    def __init__(self, name: str):
        self.name = name
        self.functions: List[FuncDump] = []


# Regex for opcode lines — VLD uses fixed-ish columns
# Format: spaces + idx + flags + E/blank + >/blank + OPCODE_NAME + rest
# The rest has: fetch_col + ext_col + return_col + operands_col
# But the exact positions vary. Let's parse by finding the opcode name first,
# then splitting the remainder into ext, return, operands.

OPCODE_RE = re.compile(
    r"^\s*(\d+)(\*?)\s+"   # idx
    r"([E ])\s*"           # entry marker
    r"(?:>\s*)*"           # zero or more > jump target markers
    r"([A-Z_][A-Z0-9_]*)"  # opcode name
    r"(.*)"                # rest of line
)

# The "rest" part has a specific layout:
#   spaces + [fetch] + spaces + [ext_val] + spaces + [return_var] + spaces + [operands]
# Examples of "rest":
#   "                                             !0      <array>"
#   "                                             'data'"
#   "                                    0  $0      "
#   "                                          ~1      'data'"
#   "                                                   ~1, !0"
#   "                                             !0, ->8"
#   "                                         8          !19, ~178"

REST_RE = re.compile(
    r"^(\s*)"                    # leading spaces (fetch area)
    r"(?:(\d+)\s+)?"             # optional ext value
    r"(?:([~$]\d+)\s+)?"         # optional return var
    r"(.*)$"                     # operands
)


def parse_operands_raw(rest: str, opcode_end_pos: int) -> Tuple[str, str, str]:
    """
    Given the rest of line after the opcode name, extract (ext_val, return_var, operands).

    The columns after the opcode are roughly:
      fetch_col  ext_col  return_col  operands_col

    We detect by looking for patterns:
    - ext is a small number (or empty)
    - return is ~N, $N, !N (or empty)
    - operands is everything else
    """
    rest = rest.rstrip()
    if not rest.strip():
        return "", "", ""

    # Find the last ~N/$N before operands (this is the return var)
    # Strategy: find the return variable which is typically ~N or $N or !N
    # followed by whitespace then operands

    tokens = rest.split()

    ext_val = ""
    ret_var = ""
    operands = ""

    if not tokens:
        return "", "", ""

    # Classify tokens: ext (small int), return (~N/$N), operands (everything else)
    classified = []
    for t in tokens:
        if re.match(r"^\d+$", t) and int(t) < 10000:
            classified.append(("ext", t))
        elif re.match(r"^[~$]\d+$", t):
            classified.append(("ret", t))
        elif re.match(r"^!\d+$", t):
            # !N could be return or operand depending on position
            classified.append(("bang", t))
        else:
            classified.append(("oper", t))

    # Walk through: first ext (if any), then ret (if any), rest is operands
    idx = 0

    # Skip ext
    if idx < len(classified) and classified[idx][0] == "ext":
        ext_val = classified[idx][1]
        idx += 1

    # Check for return var (~N or $N)
    if idx < len(classified) and classified[idx][0] in ("ret", "bang"):
        # Only treat as return if there are operand tokens after it
        if idx + 1 <= len(classified):
            ret_var = classified[idx][1]
            idx += 1

    # Everything else is operands
    remaining = tokens[idx:] if idx < len(tokens) else []

    # But we need to reconstruct with commas etc from original
    # Better: extract operands from the raw rest string
    if remaining:
        # Find where operands start in the raw string
        # Look for the last classified ret/ext token position in the raw string
        raw_after_ext = rest
        if ext_val:
            p = raw_after_ext.find(ext_val)
            if p >= 0:
                raw_after_ext = raw_after_ext[p + len(ext_val):]
        if ret_var:
            p = raw_after_ext.find(ret_var)
            if p >= 0:
                raw_after_ext = raw_after_ext[p + len(ret_var):]
        operands = raw_after_ext.strip()
    else:
        # operands might be empty — the return var IS the only value
        # e.g. RETURN ~3 -> ret=~3, operands=""
        operands = ""

    return ext_val, ret_var, operands


def parse_dump(text: str) -> List[ClassDump]:
    """Parse VLD dump text into structured ClassDump/FuncDump objects."""
    classes: List[ClassDump] = []
    current_class: Optional[ClassDump] = None
    current_func: Optional[FuncDump] = None
    in_opcode_table = False

    for line in text.splitlines():
        stripped = line.strip()

        # Class header
        m = re.match(r"^Class\s+(.+):$", stripped)
        if m:
            cname = decode_ns(m.group(1))
            current_class = ClassDump(cname)
            classes.append(current_class)
            current_func = None
            in_opcode_table = False
            continue

        if re.match(r"^End of class\s+", stripped):
            current_class = None
            continue

        # Function header
        m = re.match(r"^Function\s+(.+):$", stripped)
        if m:
            fname = m.group(1)
            cname = current_class.name if current_class else ""
            current_func = FuncDump(fname, cname)
            if current_class:
                current_class.functions.append(current_func)
            in_opcode_table = False
            continue

        if re.match(r"^End of function\s+", stripped):
            current_func = None
            in_opcode_table = False
            continue

        # Dynamic function
        m = re.match(r"^Dynamic Function\s+(\d+)", stripped)
        if m:
            fname = f"__closure_{m.group(1)}"
            cname = current_class.name if current_class else ""
            current_func = FuncDump(fname, cname)
            if current_class:
                current_class.functions.append(current_func)
            in_opcode_table = False
            continue

        # End dynamic function
        if re.match(r"^End of Dynamic Function", stripped):
            current_func = None
            continue

        # Opcode table separator
        if stripped.startswith("---"):
            in_opcode_table = True
            continue

        # Compiled vars line
        if current_func and stripped.startswith("compiled vars:"):
            for cvm in re.finditer(r"(!\d+)\s*=\s*(\$\w+)", stripped):
                current_func.compiled_vars[cvm.group(1)] = cvm.group(2)
            continue

        # Opcode line
        if current_func and in_opcode_table:
            m = OPCODE_RE.match(line)
            if m:
                idx = int(m.group(1))
                is_dead = m.group(2) == "*"
                opcode = m.group(4)
                rest = m.group(5)

                ext_val, ret_var, operands_raw = parse_operands_raw(rest, m.end())

                opl = OpLine(idx, opcode, ext_val, ret_var, operands_raw, is_dead)
                current_func.ops.append(opl)

    return classes


# ---------------------------------------------------------------------------
# Operand helpers
# ---------------------------------------------------------------------------

def split_operands(raw: str) -> List[str]:
    """Split operand string into individual tokens, respecting quotes."""
    if not raw:
        return []
    parts = []
    current = []
    in_quote = None
    depth = 0
    for ch in raw:
        if ch in ("'", '"') and in_quote is None:
            in_quote = ch
            current.append(ch)
        elif ch == in_quote:
            in_quote = None
            current.append(ch)
        elif ch == "(" and in_quote is None:
            depth += 1
            current.append(ch)
        elif ch == ")" and in_quote is None:
            depth -= 1
            current.append(ch)
        elif ch == "," and in_quote is None and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def fmt(tok: str) -> str:
    """Format a single operand token for PHP output."""
    if not tok:
        return "null"
    if re.match(r"^[!~$]\d+$", tok):
        return tok
    if tok.startswith("->"):
        return tok
    if (tok.startswith("'") and tok.endswith("'")) or (tok.startswith('"') and tok.endswith('"')):
        inner = tok[1:-1]
        inner = decode_str(inner)
        return f"'{inner}'"
    if tok in ("null", "true", "false"):
        return tok
    if tok == "<array>":
        return "[]"
    # VLD constant markers
    if tok == "<true>":
        return "true"
    if tok == "<false>":
        return "false"
    if tok == "<null>":
        return "null"
    m = re.match(r"^<const\s+(.+)>$", tok)
    if m:
        return m.group(1)
    if re.match(r"^-?\d+$", tok):
        return tok
    return decode_str(tok)


# ---------------------------------------------------------------------------
# PHP reconstructor
# ---------------------------------------------------------------------------

class PHPReconstructor:
    def __init__(self, classes: List[ClassDump]):
        self.classes = classes

    def reconstruct(self) -> str:
        parts = ["<?php\n"]
        for cls in self.classes:
            parts.append(self._class(cls))
        return "".join(parts).rstrip() + "\n"

    def _class(self, cls: ClassDump) -> str:
        parts = [f"class {cls.name}\n{{\n"]
        for fn in cls.functions:
            parts.append(self._function(fn))
        parts.append("}\n\n")
        return "".join(parts)

    def _rv(self, var: str, func: FuncDump) -> str:
        """Resolve VLD var name to PHP var name."""
        if not var:
            return ""
        return func.compiled_vars.get(var, var)

    def _find_catch_blocks(self, ops: List[OpLine]) -> dict:
        """Analyze opcodes to find try/catch structure.

        PHP 8.3 VLD pattern:
          [try body ops]
          JMP ->after_catch       (skip catch on success)
          CATCH 'ExceptionType'   (entry point on exception, has E flag)
          [catch body ops]
          JMP ->continue          (continue after try/catch)

        Returns dict: catch_pos -> {try_start, skip_jmp_idx, catch_end, exc_type}
        """
        catches = {}
        for i, op in enumerate(ops):
            if op.opcode != "CATCH":
                continue
            # Parse CATCH operands: "last 'Throwable'" or just "'Exception'"
            catch_opds_raw = op.operands_raw.strip()
            exc_type = "Exception"
            # Find quoted string in operands
            m_exc = re.search(r"'([^']+)'", catch_opds_raw)
            if m_exc:
                exc_type = decode_str(m_exc.group(1))

            # Find the JMP before this CATCH (skip-catch jump)
            skip_jmp = None
            skip_jmp_idx = None
            for j in range(i - 1, max(i - 8, -1), -1):
                if ops[j].opcode == "JMP" and not ops[j].is_dead:
                    skip_jmp = ops[j]
                    skip_jmp_idx = j
                    break

            if not skip_jmp:
                continue

            # Target of skip JMP = position after catch block
            jmp_opds = split_operands(skip_jmp.operands_raw)
            if not jmp_opds:
                continue
            try:
                catch_end = int(jmp_opds[0].lstrip("->"))
            except ValueError:
                continue

            # try_start: code between last flow control point and skip_jmp
            # Walk back from skip_jmp to find the first op that's a branch target
            # or a flow control point (JMPZ, FE_FETCH, etc)
            try_start = 0
            for j in range(skip_jmp_idx - 1, -1, -1):
                if ops[j].opcode in ("RECV", "RECV_INIT"):
                    try_start = j + 1
                    break
                # FE_FETCH, JMPZ etc are loop/branch targets — try starts after them
                if ops[j].opcode in ("FE_FETCH_R", "FE_FETCH_RW", "JMPZ", "JMPNZ",
                                     "JMPZ_EX", "JMPNZ_EX"):
                    try_start = j + 1
                    break

            catches[i] = {
                "try_start": try_start,
                "skip_jmp_idx": skip_jmp_idx,
                "catch_end": catch_end,
                "exc_type": exc_type,
            }

        return catches

    def _function(self, func: FuncDump) -> str:
        ops = func.ops
        fname = func.name

        # Collect RECV params
        params = []
        for op in ops:
            if op.opcode in ("RECV", "RECV_INIT"):
                php_var = self._rv(op.ret, func)
                default = ""
                opds = split_operands(op.operands_raw)
                if op.opcode == "RECV_INIT" and opds:
                    default = f" = {fmt(opds[0])}"
                params.append(f"{php_var}{default}")

        param_str = ", ".join(params)
        indent = "    " if func.class_name else ""
        inner = indent + "    "

        lines = [f"{indent}public function {fname}({param_str})\n{indent}{{\n"]

        # Call tracking for reconstructing method/function calls
        call_stack = []

        # -- Phase 1: build renaming map from opcode analysis --
        renames = self._build_renames(func)

        # -- Phase 2: find try/catch blocks --
        catch_map = self._find_catch_blocks(ops)

        # Build sets of indices to suppress
        skip_indices = set()
        for ci, info in catch_map.items():
            skip_indices.add(info["skip_jmp_idx"])  # suppress skip-catch JMP
            skip_indices.add(ci)  # suppress CATCH opcode itself

        # Build a map of catch_end positions -> catch_info (for closing braces)
        catch_end_targets = {}
        for ci, info in catch_map.items():
            catch_end_targets[info["catch_end"]] = ci

        # Track open braces for try/catch nesting
        brace_stack = []  # list of ("try"|"catch", indent_level)

        def current_inner():
            return indent + "    " + "    " * len(brace_stack)

        for idx, op in enumerate(ops):
            if op.is_dead:
                continue
            if idx in skip_indices:
                continue

            # Check if we need to close any blocks at this position
            while brace_stack:
                btype, end_pos = brace_stack[-1]
                if idx >= end_pos:
                    brace_stack.pop()
                    close_indent = indent + "    " + "    " * len(brace_stack)
                    if btype == "try":
                        # Close try, open catch — end_pos is the catch instruction index
                        info = catch_map.get(end_pos)
                        if info is not None:
                            exc = info["exc_type"]
                            lines.append(f"{close_indent}}} catch ({exc} $e) {{\n")
                            brace_stack.append(("catch", info["catch_end"]))
                    else:
                        lines.append(f"{close_indent}}}\n")
                else:
                    break

            # Check if a try block starts at this position
            for ci, info in catch_map.items():
                if info["try_start"] == idx:
                    lines.append(f"{current_inner()}try {{\n")
                    brace_stack.append(("try", ci))
                    break

            use_inner = current_inner()

            code = self._op(op, func, call_stack, ops, idx)
            if code:
                code = self._apply_renames(code, renames)
                lines.append(f"{use_inner}{code}\n")

        # Close remaining open braces
        while brace_stack:
            btype, _ = brace_stack.pop()
            close_indent = indent + "    " + "    " * len(brace_stack)
            if btype == "try":
                lines.append(f"{close_indent}}} catch (\\Throwable $e) {{\n")
                brace_stack.append(("catch", len(ops)))
            else:
                lines.append(f"{close_indent}}}\n")

        lines.append(f"{indent}}}\n\n")
        return "".join(lines)

    # ------------------------------------------------------------------
    # Variable renaming heuristics
    # ------------------------------------------------------------------

    def _build_renames(self, func: FuncDump) -> Dict[str, str]:
        """Analyze opcodes to suggest human-readable names for temp vars."""
        renames: Dict[str, str] = {}
        counters = {"row": 0, "val": 0, "res": 0, "tmp": 0, "str": 0,
                     "obj": 0, "arr": 0, "cond": 0, "iter": 0, "stmt": 0}

        # Collect all temp vars (~N and $N)
        temp_vars = set()
        for op in func.ops:
            if op.ret and re.match(r"^[\~\$]\d+$", op.ret):
                temp_vars.add(op.ret)
            for o in split_operands(op.operands_raw):
                if re.match(r"^[\~\$]\d+$", o):
                    temp_vars.add(o)

        for var in temp_vars:
            suggested = self._suggest_name(var, func, counters)
            if suggested:
                renames[var] = suggested

        return renames

    def _suggest_name(self, var: str, func: FuncDump, counters: dict) -> Optional[str]:
        """Suggest a readable name for a temp variable based on usage context."""
        ops = func.ops

        # Find all places where this var appears
        assigned_from = []   # what it's assigned from
        used_as = []         # how it's used
        ret_from = []        # opcodes that produce it as return

        for i, op in enumerate(ops):
            opds = split_operands(op.operands_raw)

            # This var is the return/result of this opcode
            if op.ret == var:
                ret_from.append(op.opcode)

                # Track what it's assigned from
                if op.opcode == "FETCH_OBJ_R" or op.opcode == "FETCH_OBJ_IS" or op.opcode == "FETCH_OBJ_FUNC_ARG":
                    for o in opds:
                        o_decoded = fmt(o).strip("'")
                        if o_decoded and not re.match(r"^[!~$]\d+$", o_decoded):
                            assigned_from.append(("prop", o_decoded))

                if op.opcode == "FETCH_DIM_R" or op.opcode == "FETCH_DIM_IS":
                    if len(opds) >= 2:
                        arr = self._rv(opds[0], func)
                        key = fmt(opds[1])
                        assigned_from.append(("dim", arr, key))

                if op.opcode == "FETCH_THIS":
                    assigned_from.append(("this",))

                if op.opcode == "DO_FCALL" or op.opcode == "DO_ICALL" or op.opcode == "DO_FCALL_BY_NAME":
                    assigned_from.append(("call",))

                if op.opcode == "ASSIGN":
                    assigned_from.append(("assign",))

                if op.opcode == "CONCAT":
                    assigned_from.append(("concat",))

                if op.opcode == "CAST":
                    assigned_from.append(("cast", op.ext_val))

                if op.opcode == "QM_ASSIGN":
                    if opds:
                        val = self._rv(opds[0], func)
                        assigned_from.append(("qm", val))

                if op.opcode == "COALESCE":
                    assigned_from.append(("coalesce",))

                if op.opcode == "IS_SMALLER" or op.opcode == "IS_SMALLER_OR_EQUAL" or \
                   op.opcode == "IS_EQUAL" or op.opcode == "IS_NOT_EQUAL":
                    assigned_from.append(("cmp",))

                if op.opcode == "ISSET_ISEMPTY_DIM_OBJ":
                    assigned_from.append(("isset",))

                if op.opcode == "TYPE_CHECK":
                    assigned_from.append(("typecheck",))

                if op.opcode == "BOOL" or op.opcode == "BOOL_NOT":
                    assigned_from.append(("bool",))

                if op.opcode == "INIT_ARRAY" or op.opcode == "ADD_ARRAY_ELEMENT":
                    assigned_from.append(("array",))

            # This var is used as operand
            if var in opds:
                used_as.append(op.opcode)

        # --- Naming rules ---

        # Rule 1: assigned from a property like $this->data → $data
        for src in assigned_from:
            if src[0] == "prop":
                prop_name = src[1]
                # Already a compiled var? skip
                if prop_name in func.compiled_vars.values():
                    continue
                return f"${prop_name}"

        # Rule 2: assigned from $this (FETCH_THIS) → $self or skip
        if any(s[0] == "this" for s in assigned_from):
            return None  # $this is implicit, var won't appear much

        # Rule 3: assigned from FETCH_DIM like ~1['id'] → $id
        for src in assigned_from:
            if src[0] == "dim":
                key = src[2].strip("'\"")
                if key and re.match(r"^[a-zA-Z_]\w*$", key):
                    return f"${key}"

        # Rule 4: result of a function/method call → $result, $rows, etc.
        if any(s[0] == "call" for s in assigned_from):
            # Check how the result is used
            if "RETURN" in used_as:
                counters["res"] += 1
                return f"$result{counters['res']}" if counters["res"] > 1 else "$result"
            counters["res"] += 1
            return f"$result{counters['res']}"

        # Rule 5: boolean/comparison result → $hasX, $isValid, $cond
        if any(s[0] in ("cmp", "bool", "isset", "typecheck") for s in assigned_from):
            # Look at the property being checked
            for src in assigned_from:
                if src[0] == "isset":
                    pass
            counters["cond"] += 1
            return f"$cond{counters['cond']}"

        # Rule 6: string concatenation → $strN
        if any(s[0] in ("concat", "coalesce") for s in assigned_from):
            counters["str"] += 1
            return f"$str{counters['str']}"

        # Rule 7: array init → $arrN
        if any(s[0] == "array" for s in assigned_from):
            counters["arr"] += 1
            return f"$arr{counters['arr']}"

        # Rule 8: cast result → follow source
        for src in assigned_from:
            if src[0] == "cast":
                # Look at what was cast — try to follow
                counters["val"] += 1
                return f"$val{counters['val']}"

        # Rule 9: QM_ASSIGN (ternary) → try to follow source
        for src in assigned_from:
            if src[0] == "qm" and len(src) > 1:
                source_var = src[1]
                if re.match(r"^\$\w+$", source_var) and source_var not in ("$this",):
                    return source_var  # reuse the source name

        # Rule 10: used in foreach context
        if "FE_FETCH_R" in used_as or "FE_FETCH_RW" in used_as:
            counters["row"] += 1
            return f"$row{counters['row']}"

        # Default: $tmpN
        if re.match(r"^\$", var):
            counters["tmp"] += 1
            return f"$tmp{counters['tmp']}"
        elif var.startswith("~"):
            counters["val"] += 1
            return f"$v{counters['val']}"

        return None

    _VAR_BOUNDARY = re.compile(r"(?<![a-zA-Z0-9_])")

    def _apply_renames(self, code: str, renames: Dict[str, str]) -> str:
        """Replace temp var names with human-readable ones in a code line."""
        if not renames:
            return code
        # Sort by length descending to avoid partial matches
        for old, new in sorted(renames.items(), key=lambda x: len(x[0]), reverse=True):
            if old == new:
                continue
            escaped = re.escape(old)
            # Match var not followed by alphanumeric or _
            code = re.sub(escaped + r"(?![a-zA-Z0-9_])", new, code)
        return code

        for idx, op in enumerate(ops):
            if op.is_dead:
                continue
            code = self._op(op, func, call_stack, ops, idx)
            if code:
                lines.append(f"{inner}{code}\n")

        lines.append(f"{indent}}}\n\n")
        return "".join(lines)

    def _find_next(self, ops: List[OpLine], idx: int, *opcodes: str) -> Optional[OpLine]:
        for j in range(idx + 1, min(idx + 4, len(ops))):
            if ops[j].opcode in opcodes:
                return ops[j]
        return None

    def _op(self, op: OpLine, func: FuncDump, cs: list,
            ops: List[OpLine], op_idx: int) -> Optional[str]:
        o = op.opcode
        opds = split_operands(op.operands_raw)
        ret = op.ret
        rv = lambda v: self._rv(v, func)

        # -- Suppress noise --
        if o in ("VERIFY_RETURN_TYPE", "OP_DATA", "CHECK_FUNC_ARG",
                 "BEGIN_SILENCE", "END_SILENCE", "NOP", "EXT_STMT",
                 "FE_RESET_R", "FE_RESET_RW"):
            return None

        # -- RECV handled in params, skip here --
        if o in ("RECV", "RECV_INIT"):
            return None

        # -- Return --
        if o == "RETURN":
            if opds:
                return f"return {rv(fmt(opds[0]))};"
            if ret:
                return f"return {rv(ret)};"
            return "return;"

        # -- ASSIGN --
        if o == "ASSIGN":
            if len(opds) >= 2:
                target = rv(opds[0])
                val = rv(fmt(opds[1]))
                return f"{target} = {val};"

        # -- ASSIGN_OBJ + OP_DATA pattern --
        if o == "ASSIGN_OBJ":
            prop = fmt(opds[0]).strip("'") if opds else "?"
            data = self._find_next(ops, op_idx, "OP_DATA")
            if data:
                val = rv(data.ret) if data.ret else fmt(data.operands_raw)
            else:
                val = "null"
            return f"$this->{prop} = {val};"

        # -- FETCH_OBJ write context --
        if o in ("FETCH_OBJ_W", "FETCH_OBJ_RW"):
            if len(opds) >= 2:
                obj = rv(fmt(opds[0]))
                prop = fmt(opds[1]).strip("'")
            elif opds:
                # Implicit $this
                prop = fmt(opds[0]).strip("'")
                obj = "$this"
            else:
                return None
            if ret:
                return f"{rv(ret)} = {obj}->{prop};"  # write handle
            return None

        if o == "FETCH_THIS":
            return None  # implicit

        # -- Property read --
        if o in ("FETCH_OBJ_R", "FETCH_OBJ_IS", "FETCH_OBJ_FUNC_ARG"):
            if len(opds) >= 2:
                prop = fmt(opds[1]).strip("'")
                if ret:
                    return f"{rv(ret)} = $this->{prop};"
            elif opds:
                prop = fmt(opds[0]).strip("'")
                if ret:
                    return f"{rv(ret)} = $this->{prop};"
            return None

        # -- Array access --
        if o in ("FETCH_DIM_R", "FETCH_DIM_W", "FETCH_DIM_IS"):
            if len(opds) >= 2:
                arr = rv(fmt(opds[0]))
                key = rv(fmt(opds[1]))
                if ret:
                    return f"{rv(ret)} = {arr}[{key}];"
            return None

        # -- ASSIGN_DIM --
        if o == "ASSIGN_DIM":
            if len(opds) >= 2:
                arr = rv(fmt(opds[0]))
                key = rv(fmt(opds[1]))
                data = self._find_next(ops, op_idx, "OP_DATA")
                if data:
                    val = rv(data.ret) if data.ret else fmt(data.operands_raw)
                else:
                    val = "null"
                return f"{arr}[{key}] = {val};"
            return None

        # -- Init calls --
        if o == "INIT_METHOD_CALL":
            obj = "$this"
            method = ""
            for p in opds:
                if re.match(r"^[!~$]\d+$", p):
                    obj = rv(p)
                else:
                    method = fmt(p).strip("'")
            cs.append({"t": "m", "obj": obj, "fn": method, "args": []})
            return None

        if o == "INIT_STATIC_METHOD_CALL":
            if not opds:
                # Empty operands = parent::__construct
                cs.append({"t": "s", "cls": "parent", "fn": "__construct", "args": []})
                return None
            parts_list = [fmt(p).strip("'") for p in opds]
            if len(parts_list) >= 2:
                cls_name = parts_list[0]
                method = parts_list[1]
            elif len(parts_list) == 1:
                cls_name = ""
                method = parts_list[0]
            else:
                cls_name = ""
                method = ""
            cs.append({"t": "s", "cls": cls_name, "fn": method, "args": []})
            return None

        if o == "INIT_NS_FCALL_BY_NAME":
            fname = fmt(opds[0]).strip("'") if opds else ""
            # NS call like Component\...\sprintf — extract bare function name
            if "\\" in fname:
                fname = fname.rsplit("\\", 1)[-1]
            cs.append({"t": "f", "fn": fname, "args": []})
            return None

        if o in ("INIT_FCALL", "INIT_FCALL_BY_NAME"):
            fname = fmt(opds[0]).strip("'") if opds else ""
            cs.append({"t": "f", "fn": fname, "args": []})
            return None

        if o in ("SEND_VAL", "SEND_VAL_EX", "SEND_VAR", "SEND_VAR_EX",
                  "SEND_REF", "SEND_VAR_NO_REF_EX", "SEND_FUNC_ARG"):
            if cs:
                if opds:
                    cs[-1]["args"].append(rv(fmt(opds[0])))
                elif ret:
                    cs[-1]["args"].append(rv(ret))
            return None

        # -- DO_FCALL: emit the call --
        if o in ("DO_FCALL", "DO_ICALL", "DO_FCALL_BY_NAME"):
            if not cs:
                return None
            call = cs.pop()
            args = ", ".join(call["args"])
            if call["t"] == "m":
                expr = f"{call['obj']}->{call['fn']}({args})"
            elif call["t"] == "s":
                expr = f"{call['cls']}::{call['fn']}({args})"
            elif call["t"] == "n":
                expr = f"new {call['cls']}({args})"
            else:
                expr = f"{call['fn']}({args})"
            if ret:
                return f"{rv(ret)} = {expr};"
            return f"{expr};"

        # -- NEW + DO_FCALL pattern --
        if o == "NEW":
            cls = fmt(opds[0]).strip("'") if opds else "stdClass"
            cs.append({"t": "n", "cls": cls, "args": []})
            return None

        # -- Control flow --
        if o == "JMPZ":
            cond = rv(fmt(opds[0])) if opds else "true"
            target = opds[1] if len(opds) > 1 else "?"
            return f"if (!({cond})) {{  /* ->{target} */"

        if o in ("JMPNZ_EX",):
            cond = rv(fmt(opds[0])) if opds else "true"
            target = opds[1] if len(opds) > 1 else "?"
            return f"if ({cond}) {{  /* ->{target} */"

        if o == "JMP":
            target = opds[0] if opds else "?"
            return f"/* goto ->{target} */"

        if o in ("JMPZ_EX",):
            return None

        # -- Foreach --
        if o in ("FE_FETCH_R", "FE_FETCH_RW"):
            arr = rv(fmt(opds[0])) if opds else "$iter"
            if len(opds) >= 3:
                k = rv(opds[1])
                v = rv(opds[2])
                return f"foreach ({arr} as {k} => {v}) {{"
            if len(opds) >= 2:
                v = rv(opds[1])
                return f"foreach ({arr} as {v}) {{"
            return f"foreach ({arr} as $item) {{"

        if o == "FE_FREE":
            return "}"

        # -- Ternary / coalesce --
        if o == "QM_ASSIGN":
            val = rv(fmt(opds[0])) if opds else "null"
            if ret:
                return f"{rv(ret)} = {val};"
            return None

        if o == "COALESCE":
            return None

        # -- Comparisons --
        if o in ("IS_SMALLER", "IS_SMALLER_OR_EQUAL", "IS_EQUAL",
                  "IS_NOT_EQUAL", "IS_IDENTICAL", "IS_NOT_IDENTICAL"):
            if len(opds) >= 2 and ret:
                a, b = rv(fmt(opds[0])), rv(fmt(opds[1]))
                op_map = {"IS_SMALLER": "<", "IS_SMALLER_OR_EQUAL": "<=",
                          "IS_EQUAL": "==", "IS_NOT_EQUAL": "!=",
                          "IS_IDENTICAL": "===", "IS_NOT_IDENTICAL": "!=="}
                return f"{rv(ret)} = {a} {op_map[o]} {b};"
            return None

        if o == "ISSET_ISEMPTY_DIM_OBJ":
            if len(opds) >= 2:
                arr = rv(fmt(opds[0]))
                key = rv(fmt(opds[1]))
                # ext_val=0 means isset, 1 means empty
                isset = "isset" if op.ext_val != "1" else "empty"
                if ret:
                    return f"{rv(ret)} = {isset}({arr}[{key}]);"
                return f"{isset}({arr}[{key}]);"
            return None

        if o == "TYPE_CHECK":
            if opds and ret:
                return f"{rv(ret)} = isset({rv(fmt(opds[0]))});"
            return None

        if o in ("BOOL_NOT", "BOOL"):
            if opds and ret:
                prefix = "!" if o == "BOOL_NOT" else "(bool)"
                return f"{rv(ret)} = {prefix}{rv(fmt(opds[0]))};"
            return None

        # -- Arithmetic --
        if o in ("ADD", "SUB", "MUL", "DIV", "MOD"):
            if len(opds) >= 2 and ret:
                op_map = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%"}
                a, b = rv(fmt(opds[0])), rv(fmt(opds[1]))
                return f"{rv(ret)} = {a} {op_map[o]} {b};"
            return None

        # -- Cast --
        if o == "CAST":
            cast_map = {"4": "int", "5": "float", "6": "string", "1": "array"}
            ct = cast_map.get(op.ext_val, "")
            if opds and ret and ct:
                return f"{rv(ret)} = ({ct}){rv(fmt(opds[0]))};"
            return None

        # -- Class constant --
        if o == "FETCH_CLASS_CONSTANT":
            if len(opds) >= 2 and ret:
                cls = fmt(opds[0]).strip("'")
                const = fmt(opds[1]).strip("'")
                return f"{rv(ret)} = {cls}::{const};"
            return None

        # -- Array init --
        if o == "INIT_ARRAY":
            if ret:
                if len(opds) >= 2:
                    return f"{rv(ret)} = [{rv(fmt(opds[1]))} => {rv(fmt(opds[0]))}];"
                if opds:
                    return f"{rv(ret)} = [{rv(fmt(opds[0]))}];"
                return f"{rv(ret)} = [];"
            return None

        if o == "ADD_ARRAY_ELEMENT":
            if ret:
                if len(opds) >= 2:
                    return f"{rv(ret)}[{rv(fmt(opds[1]))}] = {rv(fmt(opds[0]))};"
                if opds:
                    return f"{rv(ret)}[] = {rv(fmt(opds[0]))};"
            return None

        # -- ROPE folding --
        if o in ("ROPE_INIT", "ROPE_ADD"):
            return None

        if o == "ROPE_END":
            # The operands should have the last part, ret has the rope var
            if opds:
                return f"{rv(ret)} = /* ROPE */ {fmt(opds[-1])};"
            return None

        # -- CONCAT --
        if o == "CONCAT":
            if len(opds) >= 2 and ret:
                a, b = rv(fmt(opds[0])), rv(fmt(opds[1]))
                return f"{rv(ret)} = {a} . {b};"
            return None

        # -- THROW --
        if o == "THROW":
            exc = rv(fmt(opds[0])) if opds else "$e"
            return f"throw {exc};"

        # -- EXIT --
        if o == "EXIT":
            if opds:
                return f"exit({rv(fmt(opds[0]))});"
            return "exit;"

        # -- DECLARE_LAMBDA --
        if o == "DECLARE_LAMBDA_FUNCTION":
            return None  # handled in closure context

        if o.startswith("DECLARE_"):
            return None

        return None


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

def process_file(dump_path: Path) -> str:
    text = dump_path.read_text(errors="replace")
    classes = parse_dump(text)
    if not classes:
        return ""
    recon = PHPReconstructor(classes)
    return recon.reconstruct()


def main():
    parser = argparse.ArgumentParser(description="SG dump reconstructor")
    parser.add_argument("input", type=Path, help="Dump file or directory")
    parser.add_argument("-o", "--output", type=Path, help="Output file or directory")
    parser.add_argument("--batch", action="store_true", help="Batch mode")
    args = parser.parse_args()

    if args.batch or args.input.is_dir():
        in_dir = args.input
        out_dir = args.output or in_dir.parent / "recovered"
        out_dir.mkdir(parents=True, exist_ok=True)
        dumps = sorted(in_dir.glob("*.dump.txt"))
        ok = err = empty = 0
        for dp in dumps:
            try:
                code = process_file(dp)
                if not code or code.strip() == "<?php":
                    empty += 1
                    continue
                out_file = out_dir / dp.name.replace(".dump.txt", ".php")
                out_file.write_text(code)
                ok += 1
            except Exception as e:
                err += 1
                print(f"Error {dp.name}: {e}", file=sys.stderr)
        print(f"Done: {ok} ok, {empty} empty, {err} errors / {len(dumps)} total")
    else:
        code = process_file(args.input)
        if args.output:
            args.output.write_text(code)
        else:
            print(code)


if __name__ == "__main__":
    main()
