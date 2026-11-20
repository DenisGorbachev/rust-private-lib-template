#!/usr/bin/env -S nu --no-config-file
#MISE raw=true
#USAGE flag "--vault <vault>" help="1Password vault for the repository key" default="Private"

def main [
    --vault: string = "Private" # 1Password vault for the repository key.
]: nothing -> nothing {
    let root = ^git -C ($env.MISE_PROJECT_ROOT? | default $env.PWD) rev-parse --show-toplevel | complete
    if $root.exit_code != 0 { return }
    cd ($root.stdout | str trim)
    if ($env.PWD | path basename) =~ "@" { return }
    let origin = ^git config --default "" --get remote.origin.url | str trim
    if $origin !~ '(?i)^(?:(?:https?|ssh|git)://(?:[^/@]+@)?github\.com(?::\d+)?/|(?:[^/@:]+@)?github\.com:)' { return }

    let config = "fnox.toml"
    if ($config | path type) != "file" { fail "Expected a regular fnox.toml file" $config }
    ^./.mise/tasks/fix/fnox.sh
    let repo = ^gh repo view $origin --json "nameWithOwner,url" | from json
    let identity = ci-identity $vault $repo
    if $identity !~ '^AGE-SECRET-KEY-1[0-9A-Z]+$' {
        fail "The 1Password field must contain exactly one native age private key." $repo.url
    }
    update-config $config $identity
    $identity | ^gh secret set "FNOX_AGE_KEY" --repo $repo.url
    print $"Configured FNOX_AGE_KEY for ($repo.nameWithOwner)."
}

def ci-identity [vault: string, repo: record]: nothing -> string {
    let title = $repo.url | str replace --regex '^https://' ""
    let items = ^op item list --vault $vault --cache=false --format "json" | from json | where title == $title
    match ($items | length) {
        0 => {
            if "FNOX_AGE_KEY" in (^gh secret list --repo $repo.url --json "name" | from json | get --optional name) {
                fail $"GitHub already has FNOX_AGE_KEY. Restore its 1Password item in ($vault) before retrying, or explicitly rotate the key." $title
            }
            let identity = ^rage-keygen | lines | last
            {
                title: $title
                category: "PASSWORD"
                fields: [
                    {
                        id: "password"
                        type: "CONCEALED"
                        purpose: "PASSWORD"
                        label: "password"
                        value: $identity
                    }
                ]
            } | to json | ^op item create - --vault $vault out> /dev/null
            $identity
        }
        1 => {
            ^op item get ($items | first).id --vault $vault --cache=false --reveal --format "human-readable" --fields "label=password" | str trim
        }
        _ => { fail $"Multiple 1Password items match ($title) in ($vault): ($items.id | str join ', '). Resolve the duplicate titles and retry." $title }
    }
}

def update-config [config: path, identity: string]: nothing -> nothing {
    let settings = open $config
    let recipient = $identity | ^rage-keygen -y | str trim
    let staged = mktemp --suffix ".local.toml" ".ci-age-XXXXXXXX"
    let scratch = mktemp --directory
    try {
        ^cp -p $config $staged
        for provider in ["providers.age.recipients" "profiles.test.providers.age.recipients"] {
            let existing = $settings | get --optional ($provider | split row "." | into cell-path)
            if $existing != null and $recipient not-in $existing {
                {
                    recipients: ($existing | append $recipient)
                } | to toml | ^tomli copy --in-place "recipients" $staged $provider
            }
        }
        let imports = $settings.import? | default [] | prepend $staged | path expand
        let work = $scratch | path join "migration.toml"
        let bindings = $settings.profiles?.test?.secrets? | default {} | items {|name, secret|
            let key = $"profiles.test.secrets.($name | to json --raw)"
            [
                {target: $"($key).value", binding: $secret}
                {target: $"($key).sync.value", binding: $secret.sync?}
            ]
        } | flatten | where {|row| $row.binding.provider? == "age" and $row.binding.value? != null and not ($row.binding.value | can-decrypt $identity $scratch) }
        for row in $bindings {
            {
                import: $imports
                profiles: {
                    test: {
                        secrets: {
                            CI_AGE_VALUE: {provider: "age", value: $row.binding.value}
                        }
                    }
                }
            } | to toml | save --force $work
            try {
                ^fnox --config $work --profile "test" --no-defaults --no-daemon reencrypt --force --provider "age" "CI_AGE_VALUE"
            } catch {|err| fail $"Re-encryption failed for ($row.target): ($err.msg)" $row.target }
            let value = (open $work).profiles.test.secrets.CI_AGE_VALUE.value
            if not ($value | can-decrypt $identity $scratch) { fail "The CI key cannot decrypt the new ciphertext." $row.target }
            ^tomli set --in-place --filepath $staged $row.target $value
        }
        mv --force $staged $config
    } finally {
        rm -rf $staged $scratch
    }
}

def can-decrypt [identity: string, scratch: path]: string -> bool {
    let ciphertext = $scratch | path join "ciphertext"
    $in | decode base64 | save --raw --force $ciphertext
    try {
        $identity | ^rage --decrypt --identity "-" $ciphertext out+err> /dev/null
        true
    } catch {
        false
    }
}

def fail [message: string, context: string]: nothing -> error {
    error make {
        msg: $message
        label: {
            text: $context
            span: (metadata $context).span
        }
    }
}
