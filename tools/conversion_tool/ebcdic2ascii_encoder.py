import re

# This is a utility for converting literals in V8 source code from
# EBCDIC encoding to ASCII.

# The following are regex macros for all possible statement
OPEN_PAREN          = "(\()"
CLOSE_PAREN         = "(\))"
NEWLINE             = "(\\n)"
COMMA               = "(,)"
OUTSTREAM_OP        = "(<<)"
UNICODE_PRE         = "u8"
PRINT_FUNCTIONS     = "(PrintError|printf|PrintF|VFPrintF|SPrintF|sprintf|vfprintf|feprintf|FePrintF|open)"
USTR_MACRO          = "(USTR)"
STRING              = '(".*?(?<!\\\\)")'
CHAR                = "('.{1,2}')"
HEX_CHAR            = "('\\\\x[0-9A-Fa-f]{1,2}')"
IGNORE_STRING       = "\s*#\s*pragma|\s*//|extern\s+\"C\"|\s*#\s*line|#define\s+.*\sextern\s"
INCLUDE_STRING      = '\s*#\s*include\s+.*'
HEX_ENCODED_STRING  = r'(?:\\x[0-9A-Fa-f]{1,2})+'
CONCAT              = "(##)"
STRINGIFY           = "(#{1}\w+)"
WHITESPACE          = "(\s*)"
SPLIT_TOKEN_LIST    = [ PRINT_FUNCTIONS, USTR_MACRO, COMMA, NEWLINE, UNICODE_PRE, OPEN_PAREN, CLOSE_PAREN, OUTSTREAM_OP, STRING, CHAR, HEX_CHAR,  CONCAT, STRINGIFY ]

EBCDIC_PRAGMA_START  = re.compile(r'\s*#pragma\s+convert\s*\(\s*\"IBM-1047\"\s*\)|\s*#pragma\s+convert\s*\(\s*\"ibm-1047\"\s*\)')
EBCDIC_PRAGMA_END    = re.compile(r"\s*#pragma\s+convert\s*\(\s*pop\s*\)")
MULTILINE_COMMENT_START  = re.compile(r"^\s*/\*")
MULTILINE_COMMENT_END    = re.compile(r".*\*/\s*")

#ignore lines starting with
IGNORE_RE = re.compile(IGNORE_STRING)

#regex for include header statements
INCLUDE_RE = re.compile(INCLUDE_STRING)
MULTIPLE_HEADERS = re.compile('\s*(\S+)(.*)')
FILE_QUOTES_RE = re.compile('\s*#\s*include\s+"(.*)"')
FILE_BRACKETS_RE = re.compile('\s*#\s*include\s+<(.*)>')
FILE_END_RE = re.compile('(.*)/([a-z0-9_\.\-]*)\s*')
ABSOLUTE_RE = re.compile('\s*(/.*)')
DOT = re.compile('(.*)\.(.*)')

#line continuations
BACKSLASH_RE = re.compile('(.+)\\\\\s*\\n')

#C-string literals in the source
DEFINE_RE             = re.compile(r'#pragma|#import|#error|#define|#undef|#endif|#if|#ifdef|#else|#elseif|#elif')
OUTSTREAM_OP_RE       = re.compile(OUTSTREAM_OP)
CLOSE_PAREN_RE        = re.compile(CLOSE_PAREN)
STRING_RE             = re.compile(STRING)
CHAR_RE               = re.compile(CHAR)
NEWLINE_RE            = re.compile(NEWLINE)
HEX_ENCODED_STRING_RE = re.compile(HEX_ENCODED_STRING)
PRINT_FUNCTIONS_RE    = re.compile(PRINT_FUNCTIONS)
USTR_MACRO_RE         = re.compile(USTR_MACRO)
STRINGIFY_RE          = re.compile(STRINGIFY)
OPEN_PAREN_RE         = re.compile(OPEN_PAREN)
CLOSE_PAREN_RE        = re.compile(CLOSE_PAREN)
SPLIT_RE              = re.compile(('|').join(SPLIT_TOKEN_LIST))

#TOKENIZER FOR string literal
ESCAPE_RE    = re.compile(r'\\n|\\t|\\v|\\r|\\f|\\a|\\b|\\\'|\\\"|\\\\|\\0')
HEX_RE       = re.compile(r"(\\x[0-9A-Fa-f]{1,2})")
OCTAL_RE     = re.compile(r"(\\[0-7]{1,3})")
UNICODE_RE1  = re.compile(r"(\\u\[0-9A-Fa-f]{1,4})")
UNICODE_RE2  = re.compile(r"(\\U\[0-9A-Fa-f]{1,8})")
ENCODING_RE  = re.compile(r"(\\x[0-9A-Fa-f]{1,2} |\\\\[0-7]{1,3} |\\\\u\[0-9A-Fa-f]{1,4} |\\\\U\[0-9A-Fa-f]{1,8})")

PRINTF_RE=re.compile('%{1}\s*[-+#0]*\s*[0-9]*[.]*[0-9]*[hljztL]*[iduoxXffFeEgGaAcspn]+')


#CONVERSION TABLES
ESCAPE_LIT = {"\\n":'\n', "\\t":'\t', "\\v":'\v', "\\r":'\r',  "\\f":'\f',
              "\\a":'\a', "\\b":'\b', "\\'":'\'', "\\\"":'\"', "\\\\":'\\',
              "\\0":'\0'}

ASCII_TO_EBCDIC = [
0,1,2,3,55,45,46,47,22,5,21,11,12,13,14,15,
16,17,18,19,60,61,50,38,24,25,63,39,28,29,30,31,
64,79,127,123,91,108,80,125,77,93,92,78,107,96,75,97,
240,241,242,243,244,245,246,247,248,249,122,94,76,126,110,111,
124,193,194,195,196,197,198,199,200,201,209,210,211,212,213,214,
215,216,217,226,227,228,229,230,231,232,233,74,224,90,95,109,
121,129,130,131,132,133,134,135,136,137,145,146,147,148,149,150,
151,152,153,162,163,164,165,166,167,168,169,192,106,208,161,7,
32,33,34,35,36,21,6,23,40,41,42,43,44,9,10,27,
48,49,26,51,52,53,54,8,56,57,58,59,4,20,62,225,
65,66,67,68,69,70,71,72,73,81,82,83,84,85,86,87,
88,89,98,99,100,101,102,103,104,105,112,113,114,115,116,117,
118,119,120,128,138,139,140,141,142,143,144,154,155,156,157,158,
159,160,170,171,172,173,174,175,176,177,178,179,180,181,182,183,
184,185,186,187,188,189,190,191,202,203,204,205,206,207,218,219,
220,221,222,223,234,235,236,237,238,239,250,251,252,253,254,255]

def EncodeInEBCDIC(literal):
   convert = "";
   for byte in literal:
      hex_lit = str(hex(ASCII_TO_EBCDIC[ord(byte)]))
      convert = convert + '\\x' + hex_lit[2:4]
   return convert

def EncodeInASCII(literal):
   convert = "";
   for byte in literal:
      ascii_lit  = str(hex(ord(byte)))
      convert = convert + '\\x' + ascii_lit[2:4]
   return convert

def ConvertMacroArgs(token):
   if DEFINE_RE.match(token) or INCLUDE_RE.match(token):
      return token
   if STRINGIFY_RE.match(token):
      token = token.strip()
      return " USTR("+token+")"
   return token

def ConvertTokens(tokens):
   if not HEX_RE.search(tokens):
      return EncodeInASCII(tokens)
   else:
      return tokens

def EncodeEscapeSeq(literal):
   return EncodeInASCII(ESCAPE_LIT[literal.group(0)])

def EncodeChars(literal):
   return EncodeInASCII(literal.group(0))

def EncodePrintF(literal):
   return EncodeInEBCDIC(literal.group(0))
