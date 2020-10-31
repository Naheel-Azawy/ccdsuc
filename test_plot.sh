#!/bin/sh

python3 test.py benchmark
octave -f test_plot_speed.m
octave -f test_plot_storage.m
octave -f test_plot_rev.m
