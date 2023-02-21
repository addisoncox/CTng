#!/bin/bash

tmux new-session -d -s "my-session" -n "window1"
tmux send-keys "go run . minica" C-m
tmux split-window -v -p 50 -t "my-session:window1"
tmux send-keys "go run . minilogger 1" C-m
tmux split-window -h -t 1
tmux send-keys "go run . minilogger 2" C-m
tmux select-pane -t 0
tmux select-window -t "1"
tmux attach-session -t "my-session"
