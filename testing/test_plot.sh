#!/bin/sh

octave -f test_plot_speed.m
octave -f test_plot_storage.m
octave -f test_plot_rev.m

for f in ./benchmarks/*.pdf; do
    pdfcrop "$f"
done
