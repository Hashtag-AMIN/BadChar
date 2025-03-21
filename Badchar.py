# -*- coding: utf-8 -*-

from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator, ITab
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JLabel, JTextField, BorderFactory, BoxLayout, JFileChooser, JTabbedPane, JTextPane
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import Font
import java.awt as awt
import java.awt.datatransfer as dt
import java.awt.Toolkit as tk
import base64, urllib, codecs

badchars = [
            r"`",
            r"~",
            r"!",
            r"@",
            r"#",
            r"$",
            r"%",
            r"^",
            r"&",
            r"*",
            r"(",
            r")",
            r"-",
            r"_",
            r"=",
            r"+",
            r"]",
            r"[",
            r"}",
            r"{",
            r"\\",
            r"|",
            r"'",
            r'"',
            r";",
            r":",
            r"/",
            r"?",
            r">",
            r".",
            r"<",
            r",",
            r"‘",
            r"\`",
            r"\~",
            r"\!",
            r"\@",
            r"\#",
            r"\$",
            r"\%",
            r"\^",
            r"\&",
            r"\*",
            r"\(",
            r"\)",
            r"\-",
            r"\_",
            r"\=",
            r"\+",
            r"\]",
            r"\[",
            r"\}",
            r"\{",
            r"\\",
            r"\|",
            r"\'",
            r"\"",
            r"\;",
            r"\:",
            r"\/",
            r"\?",
            r"\>",
            r"\.",
            r"\<",
            r"\,",
            r"\‘",
            r"#!",
            r"#{",
            r"}#",
            r"#[",
            r"]#",
            r"#<",
            r"#>",
            r"^#",
            r"<!",
            r"!>",
            r"!=",
            r"@(",
            r"@{",
            r"@[",
            r"@x",
            r"$$",
            r"$%",
            r"${",
            r"}$",
            r"$(",
            r")$",
            r"$=",
            r"=$",
            r"%b",
            r"%c",
            r"%d",
            r"%e",
            r"%E",
            r"%f",
            r"%F",
            r"%g",
            r"%G",
            r"%o",
            r"%s",
            r"%x",
            r"%X",
            r"%)",
            r"%(",
            r"%;",
            r"%%",
            r"&&",
            r"&#",
            r"**",
            r"*^",
            r"*+",
            r"*/",
            r"*;",
            r"*'",
            r'*"',
            r"*`",
            r"~~",
            r"~^",
            r"``",
            r'`"',
            r"((",
            r')"',
            r")'",
            r"))",
            r"()",
            r"__",
            r"_.",
            r"._",
            r"--",
            r"++",
            r"+*",
            r"==",
            r"-=",
            r"+=",
            r"%=",
            r"/=",
            r'{{',
            r"}(",
            r"){",
            r"{$",
            r"{1",
            r"{a",
            r"{%",
            r"{!",
            r"$}",
            r"1}",
            r"a}",
            r"%}",
            r"!}",
            r"}}",
            r"{}",
            r"['",
            r'["',
            r"']",
            r'"]',
            r"[(",
            r")]",
            r")[",
            r"](",
            r"[[",
            r"[#",
            r"[<",
            r"]]",
            r">]",
            r"#]",
            r"[]",
            r"||",
            r"|\\",
            r"|/",
            r'""',
            r'"-',
            r'";',
            r'"/',
            r'"%',
            r'"#',
            r"'a",
            r'"a',
            r"a'",
            r'a"',
            r"1'",
            r'1"',
            r"'1",
            r'"1',
            r"'\"",
            r'"\'',
            r'"=',
            r"'=",
            r"''",
            r"'`",
            r"'-",
            r"';",
            r"'%",
            r"'#",
            r"‘)",
            r"‘;",
            r"'/",
            r"::",
            r":{",
            r":}",
            r":[",
            r":]",
            r":>",
            r":<",
            r":%",
            r"0:",
            r":^",
            r":/",
            r";;",
            r";{",
            r";(",
            r";|",
            r";&",
            r";#",
            r";$",
            r";`",
            r",(",
            r",{",
            r",[",
            r"//",
            r"/*",
            r"<<",
            r">>",
            r"<?",
            r"</",
            r'<"',
            r"<'",
            r"<%",
            r"<~",
            r"<#",
            r"<@",
            r"?>",
            r"/>",
            r'">',
            r"'>",
            r"%>",
            r"~>",
            r"@>",
            r"??",
            r"?=",
            r"..",
            r"./",
            r",,",
            r"\t",
            r"\n",
            r"\a",
            r"\r",
            r"\o",
            r"\x",
            r"C:",
            r"s:",
            r"0\\",
            r"0x",
            r"0o",
            r"7f",
            r"8s",
            r"*9",
            r"9j",
            r"a|",
            r"a)",
            r"a;",
            r"-7",
            r"+8",
            r"\&&",
            r"\&\&",
            r"%00",
            r"%0a",
            r"%0A",
            r"%0d",
            r"%0D",
            r"%0a%0d",
            r"/**",
            r"/**/",
            r"/*!",
            r"/*--*/",
            r"0%a0",
            r"+#1",
            r"%23",
            r"/^****",
            r"AnD",
            r"and",
            r"aND",
            r"ANd",
            r"AND",
            r"or",
            r"Or",
            r"OR",
            r"XOR",
            r"Xor",
            r"xor",
            r"xOR",
            r"xoR",
            r"false",
            r"False",
            r"faLse",
            r"FaLse",
            r"true",
            r"True",
            r"trUe",
            r"TrUe",
            r"null",
            r"Null",
            r"NULL",
            r"NuLL",
            r"nULL",
            r"NULl",
            r"None",
            r"none",
            r"NONE",
            r"NoNe",
            r"NONe",
            r"+%2F",
            r"+%2F**",
            r"+%2F**/",
            r"%25",
            r"%0b-",
            r"%0b",
            r"--+",
            r"--+-",
            r"%0d%20",
            r"%20%0a",
            r"\r\n",
            r"\n\r",
            r"{{{",
            r"}}}",
            r"{{=",
            r"<%=",
            r"[[[",
            r"]]]",
            r"${T",
            r"<!--",
            r"()//",
            r'")-\'',
            r'")-"',
            r"')-'",
            r"')-\"",
            r"}${'",
            r"}${",
            r"'}${",
            r'}${"',
            r'"}${',
            r"'\"`",
            r"\"'`",
            r"`'\"",
            r"`\"'",
            r"--><!--",
            r"--><!-- --->",
            r"'\"`>",
            r"\"'`>",
            r"`'\">",
            r"`\"'>",
            r"–>",
            r"<!--[",
            r"';-",
            r"&Tab;",
            r"&NewLine;",
            r"'))",
            r"\"))",
            r"\')",
            r"\")",
            r"\'))",
            r"1)",
            r"1))",
            r"--6",
            r"^__^",
            r"~~~>",
            r"&lt;",
            r"%3C",
            r"&lt",
            r"&LT",
            r"&LT;",
            r"&#60",
            r"&#060",
            r"&#0060",
            r"&#00060",
            r"&#000060",
            r"&#0000060",
            r"&#x3c",
            r"&#x03c",
            r"&#x003c",
            r"&#x0003c",
            r"&#x00003c",
            r"&#x000003c",
            r"&#x3c;",
            r"&#x03c;",
            r"&#x003c;",
            r"&#x0003c;",
            r"&#x00003c;",
            r"&#x000003c;",
            r"&#X3c",
            r"&#X03c",
            r"&#X003c",
            r"&#X0003c",
            r"&#X00003c",
            r"&#X000003c",
            r"&#X3c;",
            r"&#X03c;",
            r"&#X003c;",
            r"&#X0003c;",
            r"&#X00003c;",
            r"&#X000003c;",
            r"&#x3C",
            r"&#x03C",
            r"&#x003C",
            r"&#x0003C",
            r"&#x00003C",
            r"&#x000003C",
            r"&#x3C;",
            r"&#x03C;",
            r"&#x003C;",
            r"&#x0003C;",
            r"&#x00003C;",
            r"&#x000003C;",
            r"&#X3C",
            r"&#X03C",
            r"&#X003C",
            r"&#X0003C",
            r"&#X00003C",
            r"&#X000003C",
            r"&#X3C;",
            r"&#X03C;",
            r"&#X003C;",
            r"&#X0003C;",
            r"&#X00003C;",
            r"&#X000003C;",
            r"\x3c",
            r"\x3C",
            r"\u003c",
            r"\u003C",
            r"'';!--",
            r"'';!--\"",
            r"<!--<",
            r'=">"',
            r'"a=">"',
            r'"a=\'>\'"',
            r"a=`>`",
            r'a=">\'>"',
            r']">["',
            r"<///",
            r"///>",
            r"//|\\",
            r"<%<!--'%>",
            r"`xx:xx`",
            r"+[]",
            r"+[]+[]",
            r"![]",
            r"![]+[]",
            r"!![]",
            r"&colon;",
            r"<!--\x3E",
            r"Error()",
            r"Error().stack",
            r"trace()",
            r"EOF",
            r"\x00",
            r"\x07",
            r"\x0D",
            r"\x0A",
            r"\x08",
            r"\x02",
            r"\x03",
            r"\x04",
            r"\x01",
            r"\x05",
            r"\x0B",
            r"\x09",
            r"\x06",
            r"\x0C",
            r"%0C",
            r"%06",
            r"%09",
            r"%0B",
            r"%05",
            r"%01",
            r"%04",
            r"%03",
            r"%02",
            r"%08",
            r"%07",
            r"%2A",
            r"\x2A",
            r"\x3E",
            r"1/0",
            r"1%0",
            r"%()",
            r"[{}@",
            r"$($)",
            r"${}",
            r"[{}]",
            r"{;;}",
            r"{()}",
            r"&{()}",
            r"=&{()}",
            r"{!}",
            r'#{"".',
            r'}#{"".',
            r"#{''.",
            r"}#{''.",
            r"*//*",
            r"¢XSS¢",
            r"¢",
            r"¼",
            r"¾",
            r"<?='",
            r"?@[/|\]",
            r'!--"',
            r"!--'",
            r"//--><",
            r"//-->",
            r"\\');",
            r"&apos;",
            r"&quot;",
            r"&gt;",
            r"!--#exec",
            r"<!--[if",
            r"<![<!--]]",
            r"<!-- -- -->",
            r"[\xC0][\xBC]",
            r"';);\";>;",
            r"\";);';>;",
            r"///",
            r"////",
            r"/////",
            r"\/\/",
            r"〱",
            r"〵",
            r"ゝ",
            r"ー",
            r"/〱",
            r"/〵",
            r"/ゝ",
            r"/ー",
            r"/ｰ",
            r"||/",
            r"$;/",
            r"(){ :;};",
            r"w;",
            r"{1}+{1}",
            r'=DDE("',
            r"@SUM(",
            r"=10+20+cmd|",
            r"=cmd|",
            r"'-'",
            r"' '",
            r"'&'",
            r"'^'",
            r"'*'",
            r"'string'",
            r'"string"',
            r'"-"',
            r'" "',
            r'"&"',
            r'"^"',
            r'"*"',
            r'[11,"22"]',
            r'{"test":11}',
            r"(/.*/,",
            r"%0D",
            r"%26",
            r"%26%26",
            r"%09%09",
            r"\u2028",
            r"\u2029",
            r"\ufeff",
            r"/~/",
            r"\u0000",
            r"\u0001",
            r"\u0002",
            r"\u0003",
            r"\u0004",
            r"\u0005",
            r"\u0006",
            r"\u0007",
            r"\u0008",
            r"\u0009",
            r"\u000a",
            r"\u000b",
            r"\u000c",
            r"\u000d",
            r"\u000e",
            r"\u000f",
            r"\u0010",
            r"\u0011",
            r"\u0012",
            r"\u0013",
            r"\u0014",
            r"\u0015",
            r"\u0016",
            r"\u0017",
            r"\u0018",
            r"\u0019",
            r"\u001a",
            r"\u001b",
            r"\u001c",
            r"\u001d",
            r"\u001e",
            r"\u001f",
            r"\u0020",
            r"\u0021",
            r"\u0022",
            r"\u0023",
            r"\u0024",
            r"\u0025",
            r"\u0026",
            r"\u0027",
            r"\u0028",
            r"\u0029",
            r"\u002a",
            r"\u002b",
            r"\u002c",
            r"\u002d",
            r"\u002e",
            r"\u002f",
            r"\u003a",
            r"\u003b",
            r"\u003d",
            r"\u003e",
            r"\u003f",
            r"\u0040",
            r"\u005b",
            r"\u005c",
            r"\u005d",
            r"\u005e",
            r"\u005f",
            r"\u0060",
            r"\u007b",
            r"\u007c",
            r"\u007d",
            r"\u007e",
            r"\u007f",
            r"\x0a",
            r"\x0b",
            r"\x0c",
            r"\x0d",
            r"\x0e",
            r"\x0f",
            r"\x10",
            r"\x11",
            r"\x12",
            r"\x13",
            r"\x14",
            r"\x15",
            r"\x16",
            r"\x17",
            r"\x18",
            r"\x19",
            r"\x1a",
            r"\x1b",
            r"\x1c",
            r"\x1d",
            r"\x1e",
            r"\x1f",
            r"\x20",
            r"\x21",
            r"\x22",
            r"\x23",
            r"\x24",
            r"\x25",
            r"\x26",
            r"\x27",
            r"\x28",
            r"\x29",
            r"\x2a",
            r"\x2b",
            r"\x2c",
            r"\x2d",
            r"\x2e",
            r"\x2f",
            r"\x3a",
            r"\x3b",
            r"\x3d",
            r"\x3e",
            r"\x3f",
            r"\x40",
            r"\x5b",
            r"\x5c",
            r"\x5d",
            r"\x5e",
            r"\x5f",
            r"\x60",
            r"\x7b",
            r"\x7c",
            r"\x7d",
            r"\x7e",
            r"\x7f",
            r"\x85",
            r"%0c",
            r"%0e",
            r"%0f",
            r"%10",
            r"%11",
            r"%12",
            r"%13",
            r"%14",
            r"%15",
            r"%16",
            r"%17",
            r"%18",
            r"%19",
            r"%1a",
            r"%1b",
            r"%1c",
            r"%1d",
            r"%1e",
            r"%1f",
            r"%20",
            r"%21",
            r"%22",
            r"%24",
            r"%27",
            r"%28",
            r"%29",
            r"%2a",
            r"%2b",
            r"%2c",
            r"%2d",
            r"%2e",
            r"%2f",
            r"%3a",
            r"%3b",
            r"%3c",
            r"%3d",
            r"%3e",
            r"%3f",
            r"%40",
            r"%5b",
            r"%5c",
            r"%5d",
            r"%5e",
            r"%5f",
            r"%60",
            r"%7b",
            r"%7c",
            r"%7d",
            r"%7e",
            r"%7f",
            r"%85",
            ]

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BadChar")

        callbacks.registerIntruderPayloadGeneratorFactory(self)

        self.initUI()
        self.generateWordlist(None)
        print("\nExtension loaded: BadChar Wordlist Generator\nThis tool allows you to generate custom wordlists with bad characters, encoding options, "
            "and add prefix/suffix in BadChars or Custom payloads.\n\n\n\n\nHashtag_AMIN\nhttps://github.com/Hashtag-AMIN\nHappy Hunting ;)")

    def initUI(self):
        self.tabbedPane = JTabbedPane()
        self.generatorPanel = JPanel()
        self.generatorPanel.setLayout(BoxLayout(self.generatorPanel, BoxLayout.Y_AXIS))
        self.generatorPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 10, 20))

        self.prefixField = JTextField(10)
        self.suffixField = JTextField(10)
        prefixLabel = JLabel("Prefix:")
        suffixLabel = JLabel("Suffix:")

        self.base64Button = JButton("Base64 Encode", actionPerformed=self.base64Encode)
        self.urlEncodeButton = JButton("URL Encode", actionPerformed=self.urlEncode)
        self.htmlEncodeButton = JButton("HTML Encode", actionPerformed=self.htmlEncodeChar)
        self.unicodeEncodeButton = JButton("Unicode Encode", actionPerformed=self.unicodeEncodeChar)
        self.hexEncodeButton = JButton("Hex Encode", actionPerformed=self.hexEncodeChar)

        self.generateButton = JButton("Generate/Reset", actionPerformed=self.generateWordlist)
        self.applyButton = JButton("Apply Prefix/Suffix", actionPerformed=self.applyPrefixSuffix)
        self.clearButton = JButton("Clear Wordlist", actionPerformed=self.clearWordlist)
        self.copyButton = JButton("Copy to Clipboard", actionPerformed=self.copyToClipboard)
        self.saveButton = JButton("Save to File", actionPerformed=self.saveToFile)

        topPanel = JPanel()
        topPanel.add(prefixLabel)
        topPanel.add(self.prefixField)
        topPanel.add(suffixLabel)
        topPanel.add(self.suffixField)
        topPanel.add(self.applyButton)

        encodingPanel = JPanel()
        encodingPanel.add(self.base64Button)
        encodingPanel.add(self.urlEncodeButton)
        encodingPanel.add(self.htmlEncodeButton)
        encodingPanel.add(self.unicodeEncodeButton)
        encodingPanel.add(self.hexEncodeButton)

        self.wordlistArea = JTextArea()
        self.wordlistArea.setLineWrap(True)
        self.wordlistArea.setWrapStyleWord(True)
        scrollPane = JScrollPane(self.wordlistArea)
        scrollPane.setBorder(BorderFactory.createEmptyBorder(10, 80, 10, 60))
        scrollPane.setPreferredSize(awt.Dimension(1000, 500))

        bottomPanel = JPanel()
        bottomPanel.add(self.generateButton)
        bottomPanel.add(self.clearButton)
        bottomPanel.add(self.copyButton)
        bottomPanel.add(self.saveButton)

        self.tabbedPane.addTab("Wordlist Generator", self.generatorPanel)

        self.infoPanel = JPanel()
        self.infoPanel.setLayout(BoxLayout(self.infoPanel, BoxLayout.Y_AXIS))
        self.infoPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        helpTextPane = JTextPane()
        helpTextPane.setEditable(False)

        style = SimpleAttributeSet()
        StyleConstants.setAlignment(style, StyleConstants.ALIGN_CENTER)
        StyleConstants.setFontSize(style, 16)
        StyleConstants.setBold(style, True)

        doc = helpTextPane.getStyledDocument()
        doc.setParagraphAttributes(0, doc.getLength(), style, False)
        doc.insertString(doc.getLength(), "\n\n\n\n\n\nBadChar Document\n\n", style)
        doc.insertString(doc.getLength(), 
            "This tool allows you to generate custom wordlists with bad characters, encoding options,\n "
            "and add prefix/suffix in BadChars or Custom payloads.\n\nUse Generation wordlist button to add BadChar wordlist\n > Then can add prefix & suffix \n > and/or encode all payloads or characters\n\nOr can add simple list of BadChar in Intruder\n > Send request to intruder\n > In Payload type meno select Extention-generated\n\t > Select generator to BadChar and Start Attack", 
            style
        )

        doc.insertString(doc.getLength(), "\n\n\nHashtag_AMIN\n", style)
        doc.insertString(doc.getLength(), "https://github.com/Hashtag-AMIN\n", style)
        doc.insertString(doc.getLength(), "Happy Hunting ;)", style)
        
        self.infoPanel.add(helpTextPane)
        self.tabbedPane.addTab("Help & Resources", self.infoPanel)

        headerLabel = JLabel("BadChar Wordlist Generator")
        headerLabel.setFont(Font("SansSerif", Font.BOLD, 16))
        headerLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 900))
        headerLabel.setAlignmentX(JPanel.RIGHT_ALIGNMENT)

        self.generatorPanel.add(headerLabel)
        self.generatorPanel.add(bottomPanel)
        self.generatorPanel.add(topPanel)
        self.generatorPanel.add(encodingPanel)
        self.generatorPanel.add(scrollPane)
        
        self._callbacks.customizeUiComponent(self.tabbedPane)
        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "BadChar"

    def getUiComponent(self):
        return self.tabbedPane

    def generateWordlist(self, event):
        self.base_wordlist = badchars
        self.wordlistArea.setText("\n".join(self.base_wordlist))

    def clearWordlist(self, event):
        self.wordlistArea.setText("")

    def applyPrefixSuffix(self, event):
        prefix = self.prefixField.getText()
        suffix = self.suffixField.getText()
        words = self.wordlistArea.getText().splitlines()
        updated_words = ["{}{}{}".format(prefix, word.encode("utf-8"), suffix) for word in words]
        self.wordlistArea.setText("\n".join(updated_words))

    def base64Encode(self, event):
        words = self.wordlistArea.getText().splitlines()
        encoded_words = [base64.b64encode(word.encode("utf-8")).decode("utf-8") for word in words]
        self.wordlistArea.setText("\n".join(encoded_words))

    def urlEncode(self, event):
        words = self.wordlistArea.getText().splitlines()
        encoded_words = [urllib.quote(word.encode("utf-8"), safe='') for word in words]
        self.wordlistArea.setText("\n".join(encoded_words))

    def htmlEncodeChar(self, event):
        words = self.wordlistArea.getText().splitlines()
        encoded_words = ["".join("&#{};".format(ord(char)) for char in word) for word in words]
        self.wordlistArea.setText("\n".join(encoded_words))

    def unicodeEncodeChar(self, event):
        words = self.wordlistArea.getText().splitlines()
        encoded_words = ["".join("\\u{:04x}".format(ord(char)) for char in word) for word in words]
        self.wordlistArea.setText("\n".join(encoded_words))

    def hexEncodeChar(self, event):
        words = self.wordlistArea.getText().splitlines()
        encoded_words = ["".join("\\x{:02x}".format(ord(char)) for char in word) for word in words]
        self.wordlistArea.setText("\n".join(encoded_words))

    def copyToClipboard(self, event):
        wordlist = self.wordlistArea.getText()
        clipboard = tk.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(dt.StringSelection(wordlist), None)

    def saveToFile(self, event):
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("Save Wordlist to File")
        if fileChooser.showSaveDialog(self.generatorPanel) == JFileChooser.APPROVE_OPTION:
            file_path = fileChooser.getSelectedFile().getAbsolutePath()
            with codecs.open(file_path, "w", "utf-8") as f:
                f.write(self.wordlistArea.getText())
            self._callbacks.printOutput("Wordlist saved to {}.".format(file_path))

    def getGeneratorName(self):
        return "BadChar"

    def createNewInstance(self, attack):
        self.base_wordlist = self.wordlistArea.getText().splitlines()
        return BadCharactersPayloadGenerator(self._callbacks, self.base_wordlist)


class BadCharactersPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, callbacks, wordlist):
        self._callbacks = callbacks
        self._payloads = wordlist
        self._current_index = 0
        print("Loaded {} payloads".format(len(self._payloads)))

    def hasMorePayloads(self):
        return self._current_index < len(self._payloads)

    def getNextPayload(self, baseValue):
        if self.hasMorePayloads():
            payload = self._payloads[self._current_index]
            self._current_index += 1
            return payload.encode("utf-8")
        return None

    def reset(self):
        self._current_index = 0
