#!/bin/bash
tmux new -d -s "logger_ca"

tmux send-keys "go run . lcmonitor" C-m
tmux split-window -v
tmux send-keys "go run . minica" C-m
tmux split-window -h
tmux send-keys "go run . minilogger 1" C-m
tmux split-window -h
tmux send-keys "go run . minilogger 2" C-m

tmux select-pane -t 0
tmux attach-session -t "logger_ca"
