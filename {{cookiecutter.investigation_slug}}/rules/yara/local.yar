// Place Yara rules in this file.
// Non-rule lines should be prepended with comments.


// Category_rulename : TLP or other tags
rule dev_example : TLPRED tag2 tag3
{
    meta:
        author = "{{cookiecutter.full_name }}"
        description = "{{ cookiecutter.investigation_name }}"
        date = "{{ cookiecutter.date }}"
        filetype = "file type"
        md5 = "md5 hash"
        md5_2 = "md5 additional"
    strings:
        $a = {BE EF}
        $b = {CO FF EE}
        $c = "BEEF FLAVORED COFFEE"
    condition:
        $a or $b or $c
}

