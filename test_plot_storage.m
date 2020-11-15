figure;

vs_N = csvread("./benchmarks/test_sharing_N_vs_cost.csv");
vs_U = csvread("./benchmarks/test_sharing_U_vs_cost.csv");

xdata1 = vs_N(:,1);
ydata1 = vs_N(:,2);
xdata2 = vs_U(:,1);
ydata2 = vs_U(:,2);

test_plot_2(xdata1, ydata1, xdata2, ydata2, ...
            'Number of files (N)', ...
            'Number of users (U)', ...
            'Size in bytes')

saveas(gca, "./benchmarks/test_sharing_cost.png");
