def is_release_tag:
  type == "string" and
  test("^v?[0-9]+(\\.[0-9]+){2,}(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?\\z");

def is_catalog_tag($sha):
  is_release_tag or
  (($sha | test("^[0-9a-f]{40}\\z")) and . == ("sha:" + $sha[0:7]));

def sort_catalog:
  sort_by([(.tag | ltrimstr("v") | split(".") | map(tonumber? // 0)), .tag]) | reverse;

def add_audited_entry($sha; $tag; $rules_version):
  if ($tag | is_catalog_tag($sha)) then
    # A second release can name the same commit without superseding its recorded label.
    ([.[] | select(.sha == $sha and (.tag | is_release_tag)) | .tag][0] // $tag) as $label |
    ([{sha: $sha, tag: $label, rules_version: $rules_version}] + [.[] | select(.sha != $sha)]) |
    sort_catalog |
    "[\n" + ([.[] | "  { \"sha\": \(.sha | tojson), \"tag\": \(.tag | tojson), \"rules_version\": \(.rules_version) }"] | join(",\n")) + "\n]"
  else
    error("unsupported catalog tag: " + $tag)
  end;
