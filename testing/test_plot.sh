#!/bin/sh

python3 main.py test benchmark

cd testing || exit 1
octave -f test_plot_speed.m
octave -f test_plot_storage.m
octave -f test_plot_rev.m
