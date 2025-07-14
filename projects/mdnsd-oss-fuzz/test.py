import re
import sys
import os
import glob

class CFunctionParser:
    def __init__(self):
        self.all_functions = []
        self.fucn_hash_map = {}
        
    def get_c_files(self, path):
        c_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
        
        if os.path.isfile(path):
            _, ext = os.path.splitext(path)
            if ext.lower() in c_extensions:
                return [path]
            else:
                print(f"Warning: '{path}' doesn't appear to be a C/C++ file")
                return [path]  
        elif os.path.isdir(path):
            c_files = []
            for ext in c_extensions:
                pattern = os.path.join(path, '**', f'*{ext}')
                c_files.extend(glob.glob(pattern, recursive=True))
            
            if not c_files:
                print(f"No C/C++ files found in directory: {path}")
            else:
                print(f"Found {len(c_files)} C/C++ files in directory: {path}")
                
            return c_files
        else:
            print(f"Error: '{path}' is not a valid file or directory")
            return []
    
    def process_files(self, file_paths):
        for file_path in file_paths:
            print(f"Processing: {file_path}")
            file_functions = self.find_functions_in_file(file_path)
            
            for func in file_functions:
                func['file_path'] = file_path
                
            self.all_functions.extend(file_functions)
            print(f"  Found {len(file_functions)} functions")
        
        return self.all_functions
        
    def remove_comments_and_strings(self, code):
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
        code = re.sub(r"'(?:[^'\\]|\\.)*'", "''", code)
        return code
    
    def find_functions_in_file(self, filename):
        functions = []
        
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            return []
        except Exception as e:
            print(f"Error reading file '{filename}': {e}")
            return []
        
        clean_content = self.remove_comments_and_strings(content)
        lines = content.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if (not line or 
                line.startswith('#') or 
                line.startswith('//') or 
                line.startswith('/*') or
                line.startswith('*') or
                line.startswith('typedef') or
                line.startswith('struct ') or
                line.startswith('enum ') or
                line.startswith('union ')):
                i += 1
                continue
            
            potential_func_lines = []
            j = i
            brace_found = False
            while j < len(lines) and j < i + 5:
                potential_func_lines.append(lines[j])
                if '{' in lines[j]:
                    brace_found = True
                    break
                j += 1
            
            if not brace_found:
                i += 1
                continue
            
            combined = ' '.join(line.strip() for line in potential_func_lines)
            
            if self.is_potential_function(combined):
                func_start_line = i
                brace_line = j
                end_line = self.find_function_end(lines, brace_line)
                if end_line is not None:
                    func_info = self.extract_function_info(lines, func_start_line, end_line)
                    if func_info:
                        functions.append(func_info)
                i = end_line + 1 if end_line else j + 1
            else:
                i += 1
        
        return functions
    
    def is_potential_function(self, text):
        if '(' not in text or ')' not in text or '{' not in text:
            return False
        before_brace = text[:text.find('{')].strip()
        if before_brace.endswith(';'):
            return False
        if not re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)', before_brace):
            return False
        control_keywords = ['if', 'while', 'for', 'switch', 'sizeof', 'typeof', 'return']
        for keyword in control_keywords:
            if re.search(r'\b' + keyword + r'\s*\(', text):
                return False
        return True
    
    def find_function_end(self, lines, start_line):
        brace_count = 0
        for i in range(start_line, len(lines)):
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        return i
        return None
    
    def extract_function_info(self, lines, start_line, end_line):
        func_lines = lines[start_line:end_line + 1]
        full_function = '\n'.join(func_lines)
        signature_lines = []
        for line in func_lines:
            signature_lines.append(line)
            if '{' in line:
                brace_pos = line.find('{')
                if brace_pos > 0:
                    signature_lines[-1] = line[:brace_pos]
                elif brace_pos == 0:
                    signature_lines.pop()
                break
        signature = ' '.join(line.strip() for line in signature_lines).strip()
        func_name = self.extract_function_name(signature)
        if not func_name:
            return None
        
        return_type, params = self.parse_signature(signature, func_name)
        
        return {
            'name': func_name,
            'signature': signature,
            'full_function': full_function.strip(),
            'start_line': start_line + 1,
            'end_line': end_line + 1,
            'return_type': return_type,
            'params': params
        }
    
    def extract_function_name(self, signature):
        match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', signature)
        if match:
            potential_name = match.group(1)
            keywords = ['if', 'while', 'for', 'switch', 'sizeof', 'typeof', 'return', 
                       'static', 'extern', 'inline', 'const', 'volatile', 'unsigned', 
                       'signed', 'void', 'int', 'char', 'short', 'long', 'float', 
                       'double', 'struct', 'enum', 'union']
            if potential_name not in keywords:
                return potential_name
        return None
    
    def parse_signature(self, signature, func_name):
        name_pos = signature.find(func_name)
        if name_pos == -1:
            return "void", []
        
        return_type = signature[:name_pos].strip()
        if not return_type:
            return_type = "void"
        
        match = re.search(r'\((.*?)\)', signature[name_pos:])
        if not match:
            return return_type, []
        
        params_str = match.group(1).strip()
        if not params_str or params_str == "void":
            return return_type, []
        
        params = []
        param_parts = self.split_params(params_str)
        
        for i, param in enumerate(param_parts):
            param = param.strip()
            if not param:
                continue
            
            param_info = self.parse_parameter(param, i)
            if param_info:
                params.append(param_info)
        
        return return_type, params
    
    def split_params(self, params_str):
        params = []
        current = ""
        paren_count = 0
        
        for char in params_str:
            if char == ',' and paren_count == 0:
                params.append(current.strip())
                current = ""
            else:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                current += char
        
        if current.strip():
            params.append(current.strip())
        
        return params
    
    def parse_parameter(self, param, index):
        if '(*' in param or '( *' in param:
            match = re.search(r'\(\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', param)
            if match:
                name = match.group(1)
                return {'name': name, 'type': param}
            else:
                return {'name': f'param{index}', 'type': param}
        
        array_suffix = ""
        if '[' in param:
            array_match = re.search(r'(\[[^\]]*\])', param)
            if array_match:
                array_suffix = array_match.group(1)
                param = param[:param.find('[')]
        

        tokens = re.split(r'(\s+|\*+)', param)
        tokens = [t for t in tokens if t and not t.isspace()]
        
        if not tokens:
            return None
        
        name = None
        type_tokens = []
        
        for i in range(len(tokens) - 1, -1, -1):
            if tokens[i] != '*' and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', tokens[i]):
                type_keywords = ['void', 'int', 'char', 'short', 'long', 'float', 
                               'double', 'struct', 'enum', 'union', 'const', 
                               'volatile', 'unsigned', 'signed', 'static', 
                               'extern', 'register', 'auto']
                if tokens[i] not in type_keywords or i == len(tokens) - 1:
                    name = tokens[i]
                    type_tokens = tokens[:i] + tokens[i+1:]
                    break
        
        if not name:
            name = f'param{index}'
            type_tokens = tokens
        

        type_str = ""
        for token in type_tokens:
            if token == '*':
                type_str += token
            else:
                if type_str and not type_str.endswith('*'):
                    type_str += " "
                type_str += token
        
        type_str = type_str.strip() + array_suffix
        if not type_str:
            type_str = "int" 
        
        return {'name': name, 'type': type_str}
    
    def create_graph(self):
        for func in self.all_functions:
            self.fucn_hash_map[func['name']] = []
        for caller_func in self.all_functions:
            for func_name in self.fucn_hash_map.keys():
                pattern = r'\b' + re.escape(func_name) + r'\s*\('
                if re.search(pattern, caller_func['full_function']):
                    self.fucn_hash_map[caller_func['name']].append(func_name)
    
    def find_branch_depth(self, func_name):
        visited = set()
        self._dfs_collect(func_name, visited)
        return len(visited) - 1
    
    def _dfs_collect(self, func_name, visited):
        if func_name in visited:
            return
        
        visited.add(func_name)

        for child_func in self.fucn_hash_map.get(func_name, []):
            self._dfs_collect(child_func, visited)
    
    def find_average(self):
        sum = 0
        for func in self.fucn_hash_map:
            branch_depth = self.find_branch_depth(func)
            if branch_depth > 0:
                sum += branch_depth
        return sum / len(self.fucn_hash_map)
                    
                        

    def generate_yaml_output(self):
        self.create_graph()
        a = self.find_average()
        print("Average branch depth: ", a)

        output = ['"functions":']
        for func in self.all_functions: 
            val = self.find_branch_depth(func['name']) 
            keywords = [ "parse", "handle", "read","search","recv","send","token","match"]
            keyfunction = ["readrecv_message", "read", "ock_recvmsg"]
            if( (any(keyword in func['name'] for keyword in keywords) or any(keyfunction in func['full_function'] for keyfunction in keyfunction)) and val >= 2*a):
                print(func['name'], val)
                output.append(f'- "name": "{func["name"]}"')
                output.append(f'  "file": "{func.get("file_path", "unknown")}"')
                if func['params']:
                    output.append('  "params":')
                    for param in func['params']:
                        output.append(f'  - "name": "{param["name"]}"')
                        output.append(f'    "type": "{param["type"]}"')
                else:
                    output.append('  "params": []')
                    
                
                output.append(f'  "return_type": "{func["return_type"]}"')
                output.append(f'  "signature": "{func["signature"]}"')
        return '\n'.join(output)
    
    def save_to_file(self, input_path, output_filename=None):
        if not output_filename:
            if os.path.isdir(input_path):
                base_name = os.path.basename(input_path.rstrip('/\\'))
                output_filename = f"{base_name}_functions.yaml"
            else:
                base_name = os.path.splitext(os.path.basename(input_path))[0]
                output_filename = f"{base_name}.yaml"
        
        yaml_content = self.generate_yaml_output()
        
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
            print(f"\nOutput saved to: {output_filename}")
            return True
        except Exception as e:
            print(f"Error writing output file: {e}")
            return False

def main():
    if len(sys.argv) != 2:
        print("test.py <file_or_folder_path>")
        return
    
    input_path = sys.argv[1]
    parser = CFunctionParser()
    
    c_files = parser.get_c_files(input_path)
    
    if not c_files:
        print("No files to process.")
        return
    
    print(f"\nProcessing {len(c_files)} file(s)...")
    
    all_functions = parser.process_files(c_files)
    print(f"\nTotal functions found: {len(all_functions)}")
    
    parser.save_to_file(input_path)
    print("\nDone")

if __name__ == "__main__":
    main()