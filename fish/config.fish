if status is-interactive
    fish_vi_key_bindings

    # Commands to run in interactive sessions can go here
    alias lg='lazygit'
    # alias slp='sudo systemctl suspend'

    # upgrade arch and aur
    alias upgrade='sudo pacman -Syu; yay -Syu'

    # switches to Sync folder main directory
    alias cdh='cd ~/healthy_mind'
    alias cdw='cd ~/healthy_mind/web'
    alias cdc="cd ~/.config"
    alias cdhl="cd ~/humanlayer/"

    # startx
    alias sx="startx"

    # alias for sudo pacman -S
    alias p='sudo pacman -S'

    # alas for removing pacman packages
    alias q='sudo pacman -Rcns'

    # starts lunar vim with l
    alias l='nvim'

    alias l3='nvim ~/.config/i3/config'

    alias lf='nvim ~/.config/fish/config.fish'

    alias c="claude --dangerously-skip-permissions"

    xset r rate 200 40

    export MCP_CONFIG_PATH="~/healthy_mind/config.json"
    export KEEP_SERVER_OPEN="1"

    export GEMINI_API_KEY='AIzaSyA7TD0621_2_OM1tJLTp_MgFJn9djAi1WE'
    export EDITOR="nvim"

    alias sf="source ~/.config/fish/config.fish"
    alias lr="nvim README.md"
    alias g="gemini --yolo"
    alias gc="nvim ~/.config/ghostty/config"
    alias sw="cdh && ~/healthy_mind/web/serve.sh"

    alias crt="cursor-rust-tools --no-ui"

    alias dcu="sudo docker-compose up -d"
    alias dcd="sudo docker-compose down"

    alias xdb="~/healthy_mind/nuke_db.sh"

    # screens 
    alias csl="xrandr --output eDP-1 --auto --primary --output HDMI-1-0 --off"
    alias csm="xrandr --output HDMI-1-0 --auto --primary --output eDP-1 --off"
    alias csb="xrandr --output HDMI-1-0 --auto --primary --output eDP-1 --auto --secondary"

    alias hl="/home/jakedevar/humanlayer/humanlayer-wui/src-tauri/target/release/humanlayer-wui &"

    alias rm="rm -f"

    set -x GOPATH $HOME/go
    set -x PATH $PATH $GOPATH/bin
    set -x GOBIN $GOPATH/bin
    set -x CGO_ENABLED 1
    set -x PATH $PATH $HOME/.local/bin:$PATH

    set --export BUN_INSTALL "$HOME/.bun"
    set --export PATH $BUN_INSTALL/bin $PATH

end
