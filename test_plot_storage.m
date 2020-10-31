figure;
d = csvread("./benchmarks/test_sharing_N_vs_cost.csv");
p = plot(d(:,1), d(:,2));
hold on;
d = csvread("./benchmarks/test_sharing_U_vs_cost.csv");
p = plot(d(:,1), d(:,2));

legend("Varying the number of files (N)",
       "Varying the number of users (U)")
xlabel("Sharing variable (N/U)");
ylabel("Size in bytes");
grid on;
saveas(p, "./benchmarks/test_sharing_cost.png");

waitfor(p);
