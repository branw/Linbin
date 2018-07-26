from binaryninja import *
from collections import namedtuple
from cgi import escape
import re
import sys

Function = namedtuple('Function', ['text'])
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
        formatted_lines = []

        # Add the function signature
        signature = self.format_atoms_as_html(self.atomize_signature())
        formatted_lines.append('<span class="signature">' + signature + '</span> {')

        # Process the MLIL
        lines = self.process_block(self.blocks[0])

        # Get the maximum string length of an index in this function
        index_digits = len(str(max(lines, key=lambda item:item[0].instr_index)[0].instr_index))

        INDENTS = ['<span class="indent' + str(x) + '"> </span>   ' for x in range(20)]

        # Format each source line
        for instr, depth, atoms in lines:
            formatted_line = ''

            # Add a comment with the line index
            index, addr = instr.instr_index, instr.address
            formatted_line += '<span class="margin" id="' + str(index) + '" title="' + hex(addr) + '">/* ' + str(index).ljust(index_digits) + ' */</span> '
            
            # Add indentation
            formatted_line += ''.join(INDENTS[:depth])

            # Format the atoms
            formatted_line += self.format_atoms_as_html(atoms)

            formatted_lines.append(formatted_line)

        # Close the function signature
        formatted_lines.append('}')

        # Place the lines into an HTML template
        COLORS = ['181, 137,   0', '203,  75,  22', '220,  50,  47', '211,  54, 130', '108, 113, 196', ' 38, 139, 210', ' 42, 161, 152', '133, 153,   0']
        return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-type" content="text/html;charset=UTF-8">
<style type="text/css">
pre { font-family: Menlo, monospace; }
.signature { font-weight: 800 }
.margin { color: rgba(255, 255, 255, 0.5) }

.call { color: rgb(""" + COLORS[0] + """) }
.number { color: rgb(""" + COLORS[6] + """) }
.keyword { color: rgb(""" + COLORS[2] + """) }
.type { color: rgb(""" + COLORS[1] + """) }
.comment { color: rgb(""" + COLORS[4] + """) }
.function { color: rgb(""" + COLORS[5] + """) }
.variable { color: rgb(""" + COLORS[3] + """) }

:target { background-color: red; }
""" + '\n'.join('.indent' + str(x) + ' { background: rgba(255, 255, 255, ' + str(x/30.0) + ') }' for x in range(20)) + """
</style>
<body>
<pre>""" + '\n'.join(formatted_lines) + '\n'*200 + """</pre>
</body>
</html>"""

    def process_block(self, block, lines=None, visited=None, depth=0):
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
                    self.atomize_instr(instr.condition) +
                    [Text(') {')]))

                if instr.true < block.start or instr.true in visited:
                    lines.append((instr, depth+1,
                        [Keyword('goto'), Text(' '), LineNumber(instr.true)]))
                else:
                    self.process_block(self.mapping[instr.true], lines, visited, depth+1)

                lines.append((instr, depth, [Text('} '), Keyword('else'), Text(' {')]))

                if instr.false < block.start or instr.false in visited:
                    lines.append((instr, depth+1,
                        [Keyword('goto'), Text(' '), LineNumber(instr.false)]))
                else:
                    self.process_block(self.mapping[instr.false], lines, visited, depth+1)

                lines.append((instr, depth, [Text('}')]))

            elif instr.operation is MediumLevelILOperation.MLIL_GOTO:
                if instr.dest < block.start or instr.dest in visited:
                    lines.append((instr, depth,
                        [Keyword('goto'), Text(' '), LineNumber(instr.dest)]))
                else:
                    self.process_block(self.mapping[instr.dest], lines, visited, depth)

            else:
                lines.append((instr, depth, self.atomize_instr(instr) + [Text(';')]))

        return lines

    def atomize_instr(self, instr):
        atoms = []
        tokens = instr.tokens

        # Prefix assignments with types
        if instr.operation in [MediumLevelILOperation.MLIL_SET_VAR, MediumLevelILOperation.MLIL_SET_VAR_FIELD]:
            atoms.extend(self.atomize_type(instr.dest.type) + [Text(' ')])

        # Replace calls to immediates with actual function names
        elif instr.operation is MediumLevelILOperation.MLIL_CALL and instr.dest.operation is MediumLevelILOperation.MLIL_CONST_PTR:
            dest = self.bv.get_function_at(instr.dest.constant)
            atoms.append(Function(dest.name))
            # Discard the first token
            tokens = tokens[1:]

        # Change memory write syntax
        if instr.operation is MediumLevelILOperation.MLIL_STORE:
            size = 'uint8_t' if instr.size == 1 else ('uint16_t' if instr.size == 2 else ('uint32_t' if instr.size == 4 else 'uint64_t'))
            atoms.extend([Text('*('), Type(size), Text('*)(')] +
                self.atomize_instr(instr.dest) + [Text(') = ')] + self.atomize_instr(instr.src))

        else:
            for token in tokens:
                if token.type in [InstructionTextTokenType.PossibleAddressToken, InstructionTextTokenType.IntegerToken]:
                    atoms.append(Number(str(token)))
                elif token.type in [InstructionTextTokenType.LocalVariableToken]:
                    atoms.append(Variable(str(token)))
                elif token.type in [InstructionTextTokenType.RegisterToken]:
                    atoms.append(Keyword(str(token)))
                elif token.type in [InstructionTextTokenType.IndirectImportToken]:
                    atoms.append(Function(str(token)))
                else:
                    atoms.append(Text(str(token)))

        return atoms

    def atomize_signature(self):
        atoms = []

        ret, params = self.func.return_type, self.func.function_type.parameters

        atoms.extend(self.atomize_type(ret))
        atoms.extend([Text(' '), Function(str(self.func.name)), Text('(')])

        for i, param in enumerate(params):
            atoms.extend(self.atomize_type(param.type))
            atoms.extend([Text(' '), Variable(str(param.name))])

            if i + 1 < len(params):
                atoms.append(Text(', '))

        atoms.append(Text(')'))

        return atoms

    def atomize_type(self, t):
        atoms = []

        for token in t.tokens:
            if token.type is InstructionTextTokenType.KeywordToken:
                atoms.append(Type(str(token)))
            elif token.type is InstructionTextTokenType.TextToken:
                atoms.append(Text(str(token)))
            else:
                raise Exception('Unknown type token' + str(token))

        return atoms

    def format_atoms_as_html(self, atoms):
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
            elif type(atom) is Variable:
                html += '<span class="variable">' + atom.text + '</span>'
            elif type(atom) is LineNumber:
                num = str(atom.index)
                html += '<a class="line_number" href="#' + num + '">' + num + '</a>' 
            elif type(atom) is Text:
                html += escape(atom.text)

        return html

def create_view(bv, func):
    processor = FunctionLinearizer(bv, func)
    html = processor.create_html()

    bv.show_html_report(func.name, html)

PluginCommand.register_for_function(
    '[Linbin] Linear View',
    'Shows a linearized IL view',
    create_view)
