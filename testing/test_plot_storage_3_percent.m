figure;

data = csvread("./benchmarks/test_overhead_percent.csv");

x = data(:,1) / 1024;
y = data(:,4);

plot(x, y);
grid on;
xlabel("File size (KB)")
ylabel("Storage overhead (% of total storage)")

saveas(gca, "./benchmarks/test_overhead_percent.pdf");
