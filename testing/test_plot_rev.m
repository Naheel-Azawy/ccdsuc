figure;

rev_sizes = csvread("./benchmarks/test_sharing_revocation_speed_vs_size.csv");
rev_users = csvread("./benchmarks/test_sharing_revocation_speed_vs_U.csv");

xdata1 = rev_sizes(1:50,1) / 1e+6;
ydata1 = rev_sizes(1:50,2);
xdata2 = rev_users(1:50,1);
ydata2 = rev_users(1:50,2);

test_plot_2(xdata1, ydata1, xdata2, ydata2, ...
            'Size of the revoked file in megabytes', ...
            'Revocation time for different file sizes', ...
            'Number of users the file is shared with', ...
            'Revocation time for different number of users', ...
            'Revocation time in milliseconds')

saveas(gca, "./benchmarks/test_sharing_revocation.pdf");

%% waitfor(p);
