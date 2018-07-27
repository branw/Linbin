from binaryninja import *
from collections import namedtuple
from cgi import escape
import re
import sys

Function = namedtuple('Function', ['text'])
ImportedFunction = namedtuple('ImportedFunction', ['text'])
Variable = namedtuple('Variable', ['text'])
Comment = namedtuple('Comment', ['text'])
Number = namedtuple('Number', ['text'])
Text = namedtuple('Text', ['text'])
Keyword = namedtuple('Keyword', ['text'])
Type = namedtuple('Type', ['text'])
LineNumber = namedtuple('LineNumber', ['index'])

class FunctionLinearizer:
    def __init__(self, bv, func):
        self.bv = bv
        self.func = func
        self.blocks = func.medium_level_il.basic_blocks
        self.mapping = {block.start: block for block in self.blocks}

    def create_html(self):
        """Processes the entire function and generates HTML output"""

        formatted_lines = []

        # Add the function signature
        signature = self._format_atoms_as_html(self._atomize_signature())
        formatted_lines.append('<span class="signature">' + signature + '</span> {')

        # Process the MLIL
        lines = self._process_block(self.blocks[0])

        # Get the maximum string length of an index in this function
        index_digits = len(str(max(lines, key=lambda item:item[0].instr_index)[0].instr_index))

        # Format each source line
        for instr, depth, atoms in lines:
            formatted_line = ''

            # Add a comment with the line index
            index, addr = instr.instr_index, instr.address
            formatted_line += '<span class="line_number" id="' + str(index) + '" title="' + hex(addr) + '">/* ' + str(index).ljust(index_digits) + ' */</span> '
            
            # Add indentation
            formatted_line += '<span class="indent"> </span>   '*depth

            # Format the atoms
            formatted_line += self._format_atoms_as_html(atoms)

            formatted_lines.append(formatted_line)

        # Close the function signature
        formatted_lines.append('}')

        COLORS = {
            'green': '#a2d9af', 'red': '#de8f97', 'blue': '#80c6e9', 'cyan': '#8ee6ed',
            'lightcyan': '#b0dde4', 'orange': '#edbd81', 'yellow': '#eddfb3', 'magenta': '#dac4d1'
        }

        # Place the lines into an HTML template
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-type" content="text/html;charset=UTF-8">
<style type="text/css">
body { background: #2a2a2a; color: #e0e0e0 }
pre { font-family: Menlo, monospace }

.line_number { color: #909090 }
.indent { background: rgba(255, 255, 255, 0.1) }

.function { color: """ + COLORS['blue'] + """ }
.imported_function { color: """ + COLORS['orange'] + """ }
.variable { color: """ + COLORS['green'] + """ }
.comment { color: """ + COLORS['magenta'] + """ }
.number { color: """ + COLORS['cyan'] + """ }
.type { color: """ + COLORS['yellow'] + """ }
</style>
<body>
<pre>""" + '\n'.join(formatted_lines) + '\n'*200 + """</pre>
</body>
</html>"""

    def _process_block(self, block, lines=None, visited=None, depth=0):
        """Recursively processes basic blocks"""

        if not lines:
            lines = []
        if not visited:
            visited = set()

        # Visit the current block to prevent recursion
        visited.add(block.start)

        # Process each instruction in the block
        for instr in block:
            # Handle terminal instructions
            if instr.operation is MediumLevelILOperation.MLIL_IF:
                lines.append((instr, depth,
                    [Keyword('if'), Text(' (')] +
                    self._atomize_instr(instr.condition) +
                    [Text(') {')]))

                # Render or link to true condition block
                if instr.true < block.start or instr.true in visited:
                    lines.append((instr, depth+1,
                        [Keyword('goto'), Text(' '), LineNumber(instr.true), Text(';')]))
                else:
                    self._process_block(self.mapping[instr.true], lines, visited, depth+1)

                lines.append((instr, depth, [Text('} '), Keyword('else'), Text(' {')]))

                # Render or link to false condition block
                if instr.false < block.start or instr.false in visited:
                    lines.append((instr, depth+1,
                        [Keyword('goto'), Text(' '), LineNumber(instr.false), Text(';')]))
                else:
                    self._process_block(self.mapping[instr.false], lines, visited, depth+1)

                lines.append((instr, depth, [Text('}')]))

            # Render or link to goto blocks
            elif instr.operation is MediumLevelILOperation.MLIL_GOTO:
                if instr.dest < block.start or instr.dest in visited:
                    lines.append((instr, depth,
                        [Keyword('goto'), Text(' '), LineNumber(instr.dest), Text(';')]))
                else:
                    self._process_block(self.mapping[instr.dest], lines, visited, depth)

            # Render jump tables as switch statements
            elif instr.operation is MediumLevelILOperation.MLIL_JUMP_TO:
                lines.append((instr, depth,
                    [Keyword('switch'), Text(' (')] +
                    self._atomize_instr(instr.dest) +
                    [Text(') {')]))

                for i, target in enumerate(instr.targets):
                    target_block = self.mapping[target]
                    lines.append((instr, depth,
                        [Keyword('case '), Number('0x' + format(target_block[0].address, 'x')), Text(': ')]))

                    if target < block.start or target in visited:
                        lines.append((instr, depth+1,
                            [Keyword('goto'), Text(' '), LineNumber(target), Text(';')]))
                    else:
                        self._process_block(target_block, lines, visited, depth+1)
                        lines.append((instr, depth+1, [Keyword('break'), Text(';')]))

                    if i + 1 < len(instr.targets):
                        lines.append((instr, depth, []))

                lines.append((instr, depth, [Text('}')]))

            else:
                lines.append((instr, depth, self._atomize_instr(instr, semicolon=True)))

        return lines


    def _atomize_instr(self, instr, semicolon=False):
        """Emits atoms for an instruction"""

        atoms = []
        tokens = instr.tokens
        no_semicolon = False

        # Prefix assignments with types
        if instr.operation in [MediumLevelILOperation.MLIL_SET_VAR, MediumLevelILOperation.MLIL_SET_VAR_FIELD]:
            atoms.extend(self._atomize_type(instr.dest.type) + [Text(' ')])


        # Replace calls to immediates with actual function names
        if instr.operation is MediumLevelILOperation.MLIL_CALL and instr.dest.operation is MediumLevelILOperation.MLIL_CONST_PTR:
            # Add return value captures
            if any(instr.output):
                for i, output in enumerate(instr.output):
                    atoms.append(Variable(output.name))

                    if i + 1 < len(instr.output):
                        atoms.append(Text(', '))

                atoms.append(Text(' = '))

            # Add function name
            dest = self.bv.get_function_at(instr.dest.constant)
            if dest.symbol.type is SymbolType.ImportedFunctionSymbol:
                atoms.append(ImportedFunction(dest.name))
            else:
                atoms.append(Function(dest.name))    

            # Add parameters
            atoms.append(Text('(@@@@@@@@@@@@@@@@@@'))

            atoms.append(Text(')'))

        # Change memory write syntax
        elif instr.operation is MediumLevelILOperation.MLIL_STORE:
            size = 'uint8_t' if instr.size == 1 else ('uint16_t' if instr.size == 2 else ('uint32_t' if instr.size == 4 else 'uint64_t'))
            atoms.extend([Text('*('), Type(size), Text('*)(')] +
                self._atomize_instr(instr.dest) + [Text(') = ')] + self._atomize_instr(instr.src))

        # Show instructions that weren't lifted explicitly
        elif instr.operation is MediumLevelILOperation.MLIL_UNIMPL:
            actual_instr = self.bv.get_disassembly(instr.address)
            atoms.append(Comment('unimplemented - ' + str(actual_instr)))
            no_semicolon = True

        else:
            # Convert tokens to atoms
            for token in tokens:
                if token.type in [InstructionTextTokenType.PossibleAddressToken, InstructionTextTokenType.IntegerToken]:
                    atoms.append(Number(str(token)))
                elif token.type in [InstructionTextTokenType.LocalVariableToken]:
                    atoms.append(Variable(str(token)))
                elif token.type in [InstructionTextTokenType.RegisterToken]:
                    atoms.append(Keyword(str(token)))
                elif token.type in [InstructionTextTokenType.IndirectImportToken]:
                    atoms.append(ImportedFunction(str(token)))
                else:
                    atoms.append(Text(str(token)))

        if semicolon and not no_semicolon:
            atoms.append(Text(';'))

        return atoms

    def _atomize_signature(self):
        """Emits atoms for the signature of the current function"""

        atoms = []

        ret, params = self.func.return_type, self.func.function_type.parameters

        atoms.extend(self._atomize_type(ret))
        atoms.extend([Text(' '), Function(str(self.func.name)), Text('(')])

        for i, param in enumerate(params):
            atoms.extend(self._atomize_type(param.type))
            atoms.extend([Text(' '), Variable(str(param.name))])

            if i + 1 < len(params):
                atoms.append(Text(', '))

        atoms.append(Text(')'))

        if not self.func.can_return:
            atoms.append(Text(' __noreturn'))

        return atoms

    def _atomize_type(self, t):
        """Emits atoms for a BN type"""

        atoms = []

        for token in t.tokens:
            if token.type is InstructionTextTokenType.KeywordToken:
                atoms.append(Type(str(token)))
            elif token.type is InstructionTextTokenType.TextToken:
                atoms.append(Text(str(token)))
            else:
                raise Exception('Unknown type token' + str(token))

        return atoms

    def _format_atoms_as_html(self, atoms):
        """Joins and formats atoms in HTML tags"""

        html = ''

        for atom in atoms:
            if type(atom) is Comment:
                html += ' <span class="comment">/* ' + atom.text + ' */</span> '
            elif type(atom) is Number:
                html += '<span class="number">' + atom.text + '</span>'
            elif type(atom) is Keyword:
                html += '<span class="keyword">' + atom.text + '</span>'
            elif type(atom) is Type:
                html += '<span class="type">' + atom.text + '</span>'
            elif type(atom) is Function:
                html += '<span class="function">' + atom.text + '</span>'
            elif type(atom) is ImportedFunction:
                html += '<span class="imported_function">' + atom.text + '</span>'
            elif type(atom) is Variable:
                html += '<span class="variable">' + atom.text + '</span>'
            elif type(atom) is LineNumber:
                num = str(atom.index)
                html += '<a href="#' + num + '">' + num + '</a>' 
            elif type(atom) is Text:
                html += escape(atom.text)

        return html

def create_view(bv, func):
    bv.show_html_report(func.name, FunctionLinearizer(bv, func).create_html())

PluginCommand.register_for_function(
    '[Linbin] Linear View',
    'Shows a linearized IL view',
    create_view)
