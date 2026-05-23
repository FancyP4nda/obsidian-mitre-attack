import re

class MarkdownReader():

    def __init__(self, file_path):
        self.__file_path = file_path
        with open(file_path, 'r') as fd:
            self.__content = fd.read()

    
    def create_hyperlinks(self, techniques, domain=None):
        #regex = "\b(?<!/)T[0-9]{4}(?:\.[0-9]{3})?(?!.*\])\b"
        regex = r"(.)(T[0-9]{4}(?:\.[0-9]{3})?)(.{2})"
        techniques_by_id = {technique.id: technique for technique in techniques}

        def replace_with_hyperlink(match):
            prefix = match.group(1)
            suffix = match.group(3)
            string = match.group(2)

            if prefix == '|' and suffix == ']]':
                print(f"{string} is already an internal hyperlink")
                return match.group(0)
            else:
                print(f"creating an internal hyperlink for {string}")
                technique = techniques_by_id.get(string)
                if technique:
                    note_name = f"{technique.id} - {technique.name}.md"
                    note_path = f"{domain}/techniques/{note_name}" if domain else f"techniques/{note_name}"
                    return f" [[{note_path}|{string}]] "
                return match.group(0)

        self.__content = re.sub(regex, replace_with_hyperlink, self.__content)

        with open(self.__file_path, 'w') as fd:
            fd.write(self.__content)


    def find_techniques(self):
        regex = r"T[0-9]{4}(?:\.[0-9]{3})?"

        found_techniques = re.findall(regex, self.__content)

        return found_techniques
