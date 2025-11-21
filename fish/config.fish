if status is-interactive
    # Commands to run in interactive sessions can go here
    alias lg='lazygit'
    # alias slp='sudo systemctl suspend'

    # upgrade arch and aur
    alias upgrade='sudo pacman -Syu; yay -Syu'

    # switches to Sync folder main directory
    alias cdh='cd ~/healthy_mind'
    alias cdw='cd ~/healthy_mind/web'
    alias cdc="cd ~/.config"

    # alias for sudo pacman -S
    alias p='sudo pacman -S'

    # alas for removing pacman packages
    alias q='sudo pacman -Rcns'

    # starts lunar vim with l
    alias l='nvim'

    alias l3='nvim ~/.config/i3/config'

    alias lf='nvim ~/.config/fish/config.fish'

    xset r rate 200 40

    export GEMINI_API_KEY='AIzaSyA7TD0621_2_OM1tJLTp_MgFJn9djAi1WE'
    export EDITOR="nvim"

    alias sf="source ~/.config/fish/config.fish"
    alias lr="nvim README.md"
    alias g="gemini --yolo"
    alias gc="nvim ~/.config/ghostty/config"
    alias sd="~/healthy_mind/web/serve.sh"

    set -x GOPATH $HOME/go
    set -x PATH $PATH $GOPATH/bin
    set -x GOBIN $GOPATH/bin
    set -x CGO_ENABLED 1
    fish_vi_key_bindings
end
