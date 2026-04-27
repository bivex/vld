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
    if not s:
        return ""
    s = s.strip()

    # Map special VLD literals
    mapping = {
        "<array>": "[]",
        "<true>": "true",
        "<false>": "false",
        "<null>": "null",
    }
    if s in mapping:
        return mapping[s]

    # String literals in dump are often '...'
    if s.startswith("'") and s.endswith("'"):
        inner = s[1:-1]
        decoded = unquote_plus(inner)
        # Escape quotes for PHP output
        escaped = decoded.replace("'", "\\'")
        return f"'{escaped}'"

    if s.startswith('"') and s.endswith('"'):
        inner = s[1:-1]
        decoded = unquote_plus(inner)
        escaped = decoded.replace('"', '\\"')
        return f'"{escaped}"'

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
    r"^\s*(\d+)(\*?)\s+"  # idx
    r"([E ])\s*"  # entry marker
    r"(?:>\s*)*"  # zero or more > jump target markers
    r"([A-Z_][A-Z0-9_]*)"  # opcode name
    r"(.*)"  # rest of line
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
    r"^(\s*)"  # leading spaces (fetch area)
    r"(?:(\d+)\s+)?"  # optional ext value
    r"(?:([~$]\d+)\s+)?"  # optional return var
    r"(.*)$"  # operands
)


def parse_operands_raw(rest: str, line_end: int, opcode: str) -> Tuple[str, str, str]:
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
    # Tokens with trailing commas are operands (e.g., "$9,") — return column never has a comma
    classified = []
    for t in tokens:
        if t.endswith(","):
            classified.append(("oper", t))
            continue
        base = t.rstrip(",")
        if re.match(r"^\d+$", base) and int(base) < 10000:
            classified.append(("ext", base))
        elif re.match(r"^[!~$]\d+$", base):
            classified.append(("ret", base))
        else:
            classified.append(("oper", t))

    # Walk through: first ext (if any), then ret (if any), rest is operands
    # Special case: NEW opcode has operand (class name) BEFORE ret variable
    operand_before_ret = opcode == "NEW"
    idx = 0

    # Skip ext
    if idx < len(classified) and classified[idx][0] == "ext":
        ext_val = classified[idx][1]
        idx += 1

    if operand_before_ret:
        # NEW opcode: format varies
        # Format 1: NEW  className  $ret  (e.g., NEW self $7) — operand first
        # Format 2: NEW  $ret  'ClassName'  (e.g., NEW $11 'Class') — ret first (standard)
        if idx < len(classified):
            if classified[idx][0] == "ret" and idx + 1 < len(classified):
                # Format 2: ret first (standard)
                ret_var = classified[idx][1]
                idx += 1
            else:
                # Format 1: operand first (className like 'self', 'static', 'parent')
                # Capture className as operands, ret as second token
                cls_name_token = classified[idx][1]
                idx += 1
                if idx < len(classified) and classified[idx][0] == "ret":
                    ret_var = classified[idx][1]
                    idx += 1
                # For Format 1, operands is just the class name
                operands = cls_name_token
                return ext_val, ret_var, operands
    elif idx < len(classified) and classified[idx][0] == "ret":
        # Rule: if there are operands after it, it's definitely a return var.
        # If it's the ONLY token, it's a return var UNLESS the opcode is RETURN/SEND/etc.
        no_ret_opcodes = (
            "RETURN",
            "JMP",
            "JMPZ",
            "JMPNZ",
            "JMPZ_EX",
            "JMPNZ_EX",
            "SEND_VAR",
            "SEND_VAL",
            "SEND_VAR_EX",
            "SEND_VAR_NO_REF_EX",
            "SEND_VAR_NO_REF",
            "SEND_REF",
            "SEND_USER",
            "FE_FREE",
            "FREE",
            "ECHO",
            "THROW",
            "GOTO",
            "VERIFY_RETURN_TYPE",
            "OP_DATA",
        )
        if idx + 1 < len(classified) or opcode not in no_ret_opcodes:
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
                raw_after_ext = raw_after_ext[p + len(ext_val) :]
        if ret_var:
            p = raw_after_ext.find(ret_var)
            if p >= 0:
                raw_after_ext = raw_after_ext[p + len(ret_var) :]
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

                ext_val, ret_var, operands_raw = parse_operands_raw(
                    rest, m.end(), opcode
                )

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
    if (tok.startswith("'") and tok.endswith("'")) or (
        tok.startswith('"') and tok.endswith('"')
    ):
        inner = tok[1:-1]
        decoded = unquote_plus(inner)
        escaped = decoded.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"
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


# Alias so class methods can reference the global fmt without shadowing
fmt_global = fmt


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
        name = cls.name
        namespace = ""
        short_name = name

        if "\\" in name:
            parts = name.rsplit("\\", 1)
            namespace = parts[0]
            short_name = parts[1]

        lines = []
        if namespace:
            lines.append(f"namespace {namespace};\n\n")

        # Property detection: scan __construct for ASSIGN_OBJ to $this
        properties = set()
        for fn in cls.functions:
            for op in fn.ops:
                if op.opcode == "ASSIGN_OBJ":
                    opds = split_operands(op.operands_raw)
                    if opds and opds[0] == "$this":
                        prop = opds[1].strip("'\"")
                        if prop and re.match(r"^[a-zA-Z_]\w*$", prop):
                            properties.add(prop)

        lines.append(f"class {short_name}\n{{\n")
        for prop in sorted(properties):
            lines.append(f"    public ${prop};\n")
        if properties:
            lines.append("\n")

        for fn in cls.functions:
            lines.append(self._function(fn))
        lines.append("}\n\n")
        return "".join(lines)

    def _rv(self, var: str, func: FuncDump) -> str:
        """Resolve VLD var name to PHP var name."""
        if not var:
            return ""
        return func.compiled_vars.get(var, var)

    def _find_blocks(self, ops: List[OpLine]) -> Dict[int, Dict]:
        """Analyze opcodes to find if, else, foreach, and try/catch blocks."""
        blocks = {}  # start_idx -> block_info

        # 1. Detect Try/Catch (already implemented in specialized way)
        for i, op in enumerate(ops):
            if op.opcode == "CATCH":
                catch_opds_raw = op.operands_raw.strip()
                exc_type = "Exception"
                m_exc = re.search(r"'([^']+)'", catch_opds_raw)
                if m_exc:
                    exc_type = decode_str(m_exc.group(1))

                skip_jmp_idx = None
                for j in range(i - 1, max(i - 8, -1), -1):
                    if ops[j].opcode == "JMP":
                        skip_jmp_idx = j
                        break
                if skip_jmp_idx is None:
                    continue

                jmp_opds = split_operands(ops[skip_jmp_idx].operands_raw)
                if not jmp_opds:
                    continue
                try:
                    catch_end = int(jmp_opds[0].lstrip("->"))
                except:
                    continue

                try_start = next(
                    (
                        s
                        for s, b in blocks.items()
                        if b["type"] == "try" and b["catch_end"] == catch_end
                    ),
                    None,
                )
                if try_start is not None:
                    # Additional catch for existing try.
                    # The current catch (either the main one or the last in 'catches') ends HERE.
                    if not blocks[try_start]["catches"]:
                        blocks[try_start]["catch_end"] = i
                    else:
                        blocks[try_start]["catches"][-1]["end"] = i

                    blocks[try_start].setdefault("catches", []).append(
                        {"exc": exc_type, "end": catch_end, "start_idx": i}
                    )
                else:
                    try_start = 0
                    for j in range(skip_jmp_idx - 1, -1, -1):
                        if ops[j].opcode in ("RECV", "RECV_INIT") or any(
                            b.get("end") == j + 1 for b in blocks.values()
                        ):
                            try_start = j + 1
                            break
                blocks[try_start] = {
                    "type": "try",
                    "end": i,
                    "catch_exc": exc_type,
                    "catch_end": catch_end,
                    "skip_jmp": skip_jmp_idx,
                    "start": try_start,
                    "catches": [],
                }

        # 2. Detect If/Else and Foreach
        for i, op in enumerate(ops):
            if op.opcode in ("JMPZ", "JMPNZ", "JMPZ_EX", "JMPNZ_EX"):
                opds = split_operands(op.operands_raw)
                if len(opds) < 2:
                    continue
                try:
                    target = int(opds[-1].lstrip("->"))
                except:
                    continue

                # Check for else: if JMP before target points even further
                is_else = False
                else_target = None
                if (
                    target > 0
                    and target <= len(ops)
                    and ops[target - 1].opcode == "JMP"
                ):
                    else_opds = split_operands(ops[target - 1].operands_raw)
                    if else_opds:
                        is_else = True
                        try:
                            else_target = int(else_opds[0].lstrip("->"))
                        except:
                            is_else = False

                blocks[i] = {
                    "type": "if",
                    "end": target,
                    "is_else": is_else,
                    "else_end": else_target,
                    "start": i,
                }

            elif op.opcode in ("FE_FETCH_R", "FE_FETCH_RW"):
                opds = split_operands(op.operands_raw)
                if len(opds) < 2:
                    continue
                try:
                    target = int(opds[-1].lstrip("->"))
                except:
                    continue
                blocks[i] = {"type": "foreach", "end": target, "start": i}

        return blocks

    def _function(self, func: FuncDump) -> str:
        ops = func.ops
        fname = func.name

        # Collect RECV params
        params = []
        for op in ops:
            if op.opcode in ("RECV", "RECV_INIT"):
                opds = split_operands(op.operands_raw)
                raw_var = op.ret
                default = ""

                if raw_var:
                    # If ret exists, first operand (if any) is the default value
                    if op.opcode == "RECV_INIT" and opds:
                        default = f" = {fmt(opds[0])}"
                else:
                    # If ret empty, first operand is variable, second (if any) is default
                    if opds:
                        raw_var = opds[0]
                        if op.opcode == "RECV_INIT" and len(opds) >= 2:
                            default = f" = {fmt(opds[1])}"

                php_var = self._rv(raw_var, func)
                params.append(f"{php_var}{default}")

        param_str = ", ".join(params)
        indent = "    " if func.class_name else ""
        inner = indent + "    "

        lines = [f"{indent}public function {fname}({param_str})\n{indent}{{\n"]

        # Call tracking for reconstructing method/function calls
        call_stack = []
        # Rope folding: accumulate string parts for ROPE_INIT/ADD/END
        rope_parts = {}

        # -- Phase 1: build renaming map and blocks from opcode analysis --
        renames = self._build_renames(func)
        blocks = self._find_blocks(ops)

        # Build sets of indices to suppress
        skip_indices = set()
        for start, info in blocks.items():
            if info["type"] == "try":
                skip_indices.add(info["skip_jmp"])
                skip_indices.add(info["end"])  # suppress CATCH opcode
            elif info["type"] == "if" and info["is_else"]:
                skip_indices.add(info["end"] - 1)  # suppress the JMP to else_end

        # Track open blocks
        block_stack = []  # List of info dicts

        def get_indent():
            return indent + "    " + "    " * len(block_stack)

        for idx, op in enumerate(ops):
            if op.is_dead:
                continue

            # Check if we need to close any blocks at this position
            while block_stack:
                last = block_stack[-1]
                if idx >= last["end"]:
                    block_stack.pop()
                    close_indent = indent + "    " + "    " * len(block_stack)
                    # Special case: IF block ends and starts an ELSE
                    if last.get("type") == "if" and last.get("is_else"):
                        else_end = last["else_end"]
                        lines.append(f"{close_indent}}} else {{\n")
                        block_stack.append(
                            {"type": "else", "end": else_end, "start": last["start"]}
                        )

                    # Special case: TRY block ends and starts a CATCH
                    elif last.get("type") == "try":
                        lines.append(
                            f"{close_indent}}} catch ({last['catch_exc']} $e) {{\n"
                        )
                        block_stack.append(
                            {
                                "type": "catch",
                                "end": last["catch_end"],
                                "start": last["start"],
                                "catches": last.get("catches", []),
                            }
                        )

                    # Special case: CATCH block ends and starts ANOTHER CATCH
                    elif last.get("type") == "catch" and last.get("catches"):
                        next_catch = last["catches"].pop(0)
                        lines.append(
                            f"{close_indent}}} catch ({next_catch['exc']} $e) {{\n"
                        )
                        block_stack.append(
                            {
                                "type": "catch",
                                "end": next_catch["end"],
                                "start": last["start"],
                                "catches": last["catches"],
                            }
                        )
                    else:
                        lines.append(f"{close_indent}}}\n")
                else:
                    break

            if idx in skip_indices:
                continue

            # Check if a block starts at this position
            if idx in blocks:
                info = blocks[idx]
                curr_indent = get_indent()

                if info["type"] == "try":
                    lines.append(f"{curr_indent}try {{\n")
                    block_stack.append(
                        {
                            "type": "try",
                            "end": info["end"],
                            "start": idx,
                            "catches": info.get("catches", []),
                            "catch_exc": info["catch_exc"],
                            "catch_end": info["catch_end"],
                        }
                    )
                elif info["type"] == "if":
                    code = self._op(op, func, call_stack, ops, idx)
                    if code:
                        code = self._apply_renames(code, renames)
                        lines.append(f"{curr_indent}{code}\n")
                    block_stack.append(info)
                    continue
                elif info["type"] == "foreach":
                    code = self._op(op, func, call_stack, ops, idx)
                    if code:
                        code = self._apply_renames(code, renames)
                        lines.append(f"{curr_indent}{code}\n")
                    block_stack.append(info)
                    continue

            # Handle CATCH separately as it's the "start" of catch part of try block
            for start, info in blocks.items():
                if info["type"] == "try" and info["end"] == idx:
                    # Closing the try block is handled by 'idx >= info["end"]' logic
                    pass

            use_inner = get_indent()
            ret = op.ret
            opds_local = split_operands(op.operands_raw)

            # Rope folding logic
            if op.opcode == "ROPE_INIT":
                if ret:
                    init_parts = []
                    # ROPE_INIT operand is the first string piece
                    if opds_local:
                        init_parts.append(self._rv(fmt_global(opds_local[0]), func))
                    rope_parts[ret] = init_parts
                continue
            elif op.opcode == "ROPE_ADD":
                if len(opds_local) >= 2:
                    handle, piece_tok = opds_local[0], opds_local[1]
                    if handle in rope_parts:
                        rope_parts[handle].append(self._rv(fmt_global(piece_tok), func))
                continue
            elif op.opcode == "ROPE_END":
                if opds_local and ret:
                    handle = opds_local[0]
                    extra = opds_local[1:]
                    parts = rope_parts.get(handle, []).copy()
                    for e in extra:
                        parts.append(self._rv(fmt_global(e), func))
                    expr = " . ".join(parts) if parts else "''"
                    code_local = f"{self._rv(ret, func)} = {expr};"
                    if handle in rope_parts:
                        del rope_parts[handle]
                    lines.append(
                        f"{use_inner}{self._apply_renames(code_local, renames)}\n"
                    )
                    continue

            # Inline throw logic
            if op.opcode in ("DO_FCALL", "DO_ICALL", "DO_FCALL_BY_NAME"):
                next_i = idx + 1
                while next_i < len(ops) and ops[next_i].is_dead:
                    next_i += 1
                if next_i < len(ops) and ops[next_i].opcode == "THROW":
                    if call_stack and call_stack[-1].get("t") == "n":
                        new_ret = call_stack[-1].get("ret")
                        if split_operands(ops[next_i].operands_raw)[0] == new_ret:
                            call = call_stack[-1]
                            code_local = (
                                f"throw new {call['cls']}({', '.join(call['args'])});"
                            )
                            lines.append(
                                f"{use_inner}{self._apply_renames(code_local, renames)}\n"
                            )
                            call_stack.pop()
                            skip_indices.add(next_i)
                            continue

            code = self._op(op, func, call_stack, ops, idx)
            if code:
                code = self._apply_renames(code, renames)
                lines.append(f"{use_inner}{code}\n")

        # Close any remaining blocks
        while block_stack:
            block_stack.pop()
            close_indent = indent + "    " + "    " * len(block_stack)
            lines.append(f"{close_indent}}}\n")

        # Remove trailing implicit return; (PHP adds implicit return null)
        while lines and lines[-1].strip() in ("return;", "return null;"):
            lines.pop()
        lines.append(f"{indent}}}\n\n")
        return "".join(lines)

    def _fix_missing_returns(self, func: FuncDump):
        """Fix cases where VLD doesn't show the return variable of a call."""
        ops = func.ops
        assigned_vars = {op.ret for op in ops if op.ret}

        for i in range(len(ops) - 1):
            op = ops[i]
            if (
                op.opcode in ("DO_FCALL", "DO_ICALL", "DO_FCALL_BY_NAME", "DO_UCALL")
                and not op.ret
            ):
                # Look ahead for a variable that is used but not explicitly assigned
                next_idx = i + 1
                while next_idx < len(ops) and ops[next_idx].is_dead:
                    next_idx += 1

                if next_idx < len(ops):
                    next_op = ops[next_idx]
                    # Check operands of next opcode
                    next_opds = split_operands(next_op.operands_raw)
                    for o in next_opds:
                        if re.match(r"^[~$]\d+$", o) and o not in assigned_vars:
                            op.ret = o
                            assigned_vars.add(o)
                            break

    def _build_renames(self, func: FuncDump) -> Dict[str, str]:
        """Analyze opcodes to suggest human-readable names for temp vars."""
        self._fix_missing_returns(func)
        renames: Dict[str, str] = {}
        counters = {
            "row": 0,
            "val": 0,
            "res": 0,
            "tmp": 0,
            "str": 0,
            "obj": 0,
            "arr": 0,
            "cond": 0,
            "iter": 0,
            "stmt": 0,
        }

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
        assigned_from = []  # what it's assigned from
        used_as = []  # how it's used
        ret_from = []  # opcodes that produce it as return

        for i, op in enumerate(ops):
            opds = split_operands(op.operands_raw)

            # This var is the return/result of this opcode
            if op.ret == var:
                ret_from.append(op.opcode)

                # Track what it's assigned from
                if (
                    op.opcode == "FETCH_OBJ_R"
                    or op.opcode == "FETCH_OBJ_IS"
                    or op.opcode == "FETCH_OBJ_FUNC_ARG"
                ):
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

                if (
                    op.opcode == "DO_FCALL"
                    or op.opcode == "DO_ICALL"
                    or op.opcode == "DO_FCALL_BY_NAME"
                ):
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

                if (
                    op.opcode == "IS_SMALLER"
                    or op.opcode == "IS_SMALLER_OR_EQUAL"
                    or op.opcode == "IS_EQUAL"
                    or op.opcode == "IS_NOT_EQUAL"
                ):
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

        if any(s[0] == "this" for s in assigned_from):
            return "$this"

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
                if (
                    re.match(r"^\$[a-zA-Z_]\w*$", source_var)
                    and source_var not in ("$this",)
                    and not re.match(r"^\$\d+$", source_var)
                ):
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

    def _find_next(
        self, ops: List[OpLine], idx: int, *opcodes: str
    ) -> Optional[OpLine]:
        for j in range(idx + 1, min(idx + 4, len(ops))):
            if ops[j].opcode in opcodes:
                return ops[j]
        return None

    def _op(
        self, op: OpLine, func: FuncDump, cs: list, ops: List[OpLine], op_idx: int
    ) -> Optional[str]:
        o = op.opcode
        opds = split_operands(op.operands_raw)
        ret = op.ret
        rv = lambda v: self._rv(v, func)
        fmt = lambda v: decode_str(v)
        fmt_str = fmt_global  # Use for string VALUE contexts (needs backslash escaping)

        if o == "OP_DATA":
            return None

        # -- Suppress noise --
        if o in (
            "VERIFY_RETURN_TYPE",
            "OP_DATA",
            "CHECK_FUNC_ARG",
            "BEGIN_SILENCE",
            "END_SILENCE",
            "NOP",
            "EXT_STMT",
            "FE_RESET_R",
            "FE_RESET_RW",
        ):
            return None

        # -- RECV handled in params, skip here --
        if o in ("RECV", "RECV_INIT"):
            return None

        # -- Return --
        if o == "RETURN":
            if opds:
                return f"return {rv(fmt_str(opds[0]))};"
            if ret:
                return f"return {rv(ret)};"
            return "return;"

        # -- ASSIGN --
        if o == "ASSIGN":
            if len(opds) >= 2:
                target = rv(opds[0])
                val = rv(fmt_str(opds[1]))
                return f"{target} = {val};"

        # -- ASSIGN_OBJ + OP_DATA pattern --
        if o == "ASSIGN_OBJ":
            # property token: either from operands or from ret column
            if opds:
                tok = opds[0]
            elif op.ret:
                tok = op.ret
            else:
                tok = None
            if tok:
                if re.match(r"^[!~$]\d+$", tok):
                    prop = rv(tok)
                else:
                    prop = fmt(tok).strip("'")
            else:
                prop = "?"
            data = self._find_next(ops, op_idx, "OP_DATA")
            if data:
                # OP_DATA typically stores the value in its operands, not in ret
                opds_data = split_operands(data.operands_raw)
                if opds_data:
                    # Use first operand as value
                    val = rv(fmt_str(opds_data[0]))
                else:
                    val = "null"
            else:
                val = "null"
            # Format property access: if prop is a variable, use {$var} syntax
            if isinstance(prop, str) and prop.startswith("$"):
                prop_formatted = "{" + prop + "}"
            else:
                prop_formatted = prop
            return f"$this->{prop_formatted} = {val};"

        # -- FETCH_OBJ write context --
        if o in ("FETCH_OBJ_W", "FETCH_OBJ_RW"):
            if len(opds) >= 2:
                obj = rv(fmt(opds[0]))
                tok = opds[1]
                if re.match(r"^[!~$]\d+$", tok):
                    prop = rv(tok)
                else:
                    prop = fmt(tok).strip("'")
            elif opds:
                # Implicit $this
                tok = opds[0]
                if re.match(r"^[!~$]\d+$", tok):
                    prop = rv(tok)
                else:
                    prop = fmt(tok).strip("'")
                obj = "$this"
            else:
                return None
            if ret:
                # Format property access: if prop is a variable, use {$var} syntax
                if isinstance(prop, str) and prop.startswith("$"):
                    prop_formatted = "{" + prop + "}"
                else:
                    prop_formatted = prop
                return f"{rv(ret)} = {obj}->{prop_formatted};"  # write handle
            return None

        if o == "FETCH_THIS":
            return None  # implicit

        # -- Object / Static Props --
        if o in (
            "FETCH_OBJ_R",
            "FETCH_OBJ_W",
            "FETCH_OBJ_RW",
            "FETCH_OBJ_IS",
            "FETCH_OBJ_FUNC_ARG",
            "FETCH_OBJ_UNSET",
        ):
            if len(opds) >= 2:
                obj = rv(opds[0])
                prop_tok = opds[1]
            elif opds:
                obj = "$this"
                prop_tok = opds[0]
            else:
                return None

            prop = fmt(prop_tok).strip("'\"")
            if re.match(r"^[!~$]\d+$", prop):
                prop = "{" + rv(prop) + "}"
            expr = f"{obj}->{prop}"
            if ret:
                return f"{rv(ret)} = {expr};"
            return expr

        if o in (
            "FETCH_STATIC_PROP_R",
            "FETCH_STATIC_PROP_W",
            "FETCH_STATIC_PROP_RW",
            "FETCH_STATIC_PROP_FUNC_ARG",
        ):
            import sys

            sys.stderr.write(f"DEBUG STATIC: o={o}, raw='{op.operands_raw}'\n")
            # VLD format: fetch_col  ext_col  return_col  (whitespace separated)
            # fetch: unknown (or class name?), ext: result variable, return: property name
            cls_name = "self"
            prop_tok = None
            result_var = None

            # Parse raw line
            raw = op.operands_raw.strip()
            parts = raw.split()
            sys.stderr.write(f"DEBUG STATIC: parts={parts}\n")
            # parts: [fetch, ext, return] or [fetch, ext] or [property]
            if len(parts) >= 3:
                # ext column is result variable, return column is property
                result_var = parts[1]  # ext column
                prop_tok = parts[2]  # return column
                # try to get class name from fetch column if it's not 'unknown'
                if parts[0] != "unknown":
                    cls_name = fmt(parts[0])
            elif len(parts) == 2:
                # Maybe fetch and ext? Not sure.
                prop_tok = parts[1]
            elif len(parts) == 1:
                prop_tok = parts[0]
            else:
                prop_tok = "unknown"

            # If opds has something (maybe from split_operands), use that as fallback
            if not prop_tok or prop_tok == "unknown":
                if opds:
                    prop_tok = opds[0]
                elif op.ret:
                    prop_tok = op.ret

            sys.stderr.write(
                f"DEBUG STATIC: prop_tok={prop_tok}, result_var={result_var}\n"
            )
            if re.match(r"^[!~$]\d+$", prop_tok):
                prop = "{" + rv(prop_tok) + "}"
            else:
                prop = fmt(prop_tok).strip("'\"")

            expr = f"{cls_name}::${prop}"
            sys.stderr.write(f"DEBUG STATIC: expr={expr}\n")
            # If there is a result variable (ext column), assign to it
            if result_var:
                return f"{rv(result_var)} = {expr};"
            if ret:
                return f"{rv(ret)} = {expr};"
            return expr

        if o == "ASSIGN_OBJ":
            if len(opds) >= 3:
                obj = rv(opds[0])
                prop_tok = opds[1]
                val_tok = opds[2]
            elif len(opds) >= 2:
                obj = "$this"
                prop_tok = opds[0]
                val_tok = opds[1]
            else:
                obj = "$this"
                prop_tok = opds[0] if opds else "unknown"
                # Look for OP_DATA
                data_op = self._find_next(ops, op_idx, "OP_DATA")
                if data_op:
                    d_opds = split_operands(data_op.operands_raw)
                    val_tok = d_opds[0] if d_opds else "null"
                else:
                    val_tok = "null"

            if re.match(r"^[!~$]\d+$", prop_tok):
                prop = "{" + rv(prop_tok) + "}"
            else:
                prop = fmt(prop_tok).strip("'\"")

            val = rv(fmt(val_tok))
            return f"{obj}->{prop} = {val};"

        if o == "ASSIGN_STATIC_PROP":
            if len(opds) >= 3:
                prop_tok = opds[0]
                cls_name = fmt(opds[1]) if len(opds) > 1 else "self"
                val_tok = opds[2]
            else:
                prop_tok = opds[0] if opds else "unknown"
                cls_name = fmt(opds[1]) if len(opds) > 1 else "self"
                # Look for OP_DATA
                data_op = self._find_next(ops, op_idx, "OP_DATA")
                if data_op:
                    d_opds = split_operands(data_op.operands_raw)
                    val_tok = d_opds[0] if d_opds else "null"
                else:
                    val_tok = "null"

            if re.match(r"^[!~$]\d+$", prop_tok):
                prop = "{" + rv(prop_tok) + "}"
            else:
                prop = fmt(prop_tok).strip("'\"")

            val = rv(fmt(val_tok))
            return f"{cls_name}::${prop} = {val};"

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
                    # OP_DATA value can be in ret, operands_raw, or ext_val
                    if data.ret:
                        val = rv(data.ret)
                    elif data.operands_raw.strip():
                        val = rv(fmt(data.operands_raw.strip()))
                    elif data.ext_val:
                        val = data.ext_val
                    else:
                        val = "null"
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
                # Single operand — likely method name with implicit self:: or parent::
                # Common case: parent::__construct or parent::method
                method = parts_list[0]
                # Default to 'self::' for static calls within same class
                # Use 'parent::' for __construct and common parent methods
                if method in (
                    "__construct",
                    "__destruct",
                    "__get",
                    "__set",
                    "__isset",
                    "__unset",
                    "before",
                    "after",
                    "init",
                ):
                    cls_name = "parent"
                else:
                    cls_name = "self"
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

        if o in (
            "SEND_VAL",
            "SEND_VAL_EX",
            "SEND_VAR",
            "SEND_VAR_EX",
            "SEND_REF",
            "SEND_VAR_NO_REF_EX",
            "SEND_FUNC_ARG",
        ):
            if cs:
                if opds:
                    cs[-1]["args"].append(rv(fmt_str(opds[0])))
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
            cs.append({"t": "n", "cls": cls, "args": [], "ret": op.ret})
            return None

        # -- Control flow --
        if o in ("JMPZ", "JMPNZ", "JMPZ_EX", "JMPNZ_EX"):
            cond = rv(fmt(opds[0])) if opds else "true"
            if "NZ" in o:
                return f"if ({cond}) {{"
            return f"if (!({cond})) {{"

        if o == "JMP":
            return None

        if o in ("JMPZ_EX",):
            return None

        # -- Foreach --
        if o in ("FE_FETCH_R", "FE_FETCH_RW"):
            # FE_FETCH_R  [~key]  $iter, !value, ->exit
            # opds: iterator, value, exit_target (->N)
            # ret: key variable (if foreach($a as $k => $v))
            arr = rv(fmt(opds[0])) if len(opds) >= 1 else "$iter"
            v = rv(opds[1]) if len(opds) >= 2 else "$item"
            # opds[2] is ->N exit target, ignore
            if ret:
                # has key: foreach ($arr as $key => $value)
                k = rv(ret)
                return f"foreach ({arr} as {k} => {v}) {{"
            return f"foreach ({arr} as {v}) {{"

        if o == "FE_FREE":
            return None  # handled by block stack

        # -- Ternary / coalesce --
        if o == "QM_ASSIGN":
            val = rv(fmt_str(opds[0])) if opds else "null"
            if ret:
                return f"{rv(ret)} = {val};"
            return None

        if o == "COALESCE":
            return None

        # -- Comparisons --
        if o in (
            "IS_SMALLER",
            "IS_SMALLER_OR_EQUAL",
            "IS_EQUAL",
            "IS_NOT_EQUAL",
            "IS_IDENTICAL",
            "IS_NOT_IDENTICAL",
        ):
            if len(opds) >= 2 and ret:
                a, b = rv(fmt(opds[0])), rv(fmt(opds[1]))
                op_map = {
                    "IS_SMALLER": "<",
                    "IS_SMALLER_OR_EQUAL": "<=",
                    "IS_EQUAL": "==",
                    "IS_NOT_EQUAL": "!=",
                    "IS_IDENTICAL": "===",
                    "IS_NOT_IDENTICAL": "!==",
                }
                return f"{rv(ret)} = {a} {op_map[o]} {b};"
            return None

        if o == "ISSET_ISEMPTY_DIM_OBJ":
            if len(opds) >= 2:
                arr = rv(fmt_str(opds[0]))
                key = rv(fmt_str(opds[1]))
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
                    return f"{rv(ret)} = [{rv(fmt_str(opds[1]))} => {rv(fmt_str(opds[0]))}];"
                if opds:
                    return f"{rv(ret)} = [{rv(fmt_str(opds[0]))}];"
                return f"{rv(ret)} = [];"
            return None

        if o == "ADD_ARRAY_ELEMENT":
            if ret:
                if len(opds) >= 2:
                    return f"{rv(ret)}[{rv(fmt_str(opds[1]))}] = {rv(fmt_str(opds[0]))};"
                if opds:
                    return f"{rv(ret)}[] = {rv(fmt_str(opds[0]))};"
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
                a, b = rv(fmt_str(opds[0])), rv(fmt_str(opds[1]))
                return f"{rv(ret)} = {a} . {b};"
                return line
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


import traceback


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
                traceback.print_exc()
        print(f"Done: {ok} ok, {empty} empty, {err} errors / {len(dumps)} total")
    else:
        code = process_file(args.input)
        if args.output:
            args.output.write_text(code)
        else:
            print(code)


if __name__ == "__main__":
    main()
