vs_x = csvread("./benchmarks/test_sharing_N_vs_cost.csv"); % files
vs_y = csvread("./benchmarks/test_sharing_U_vs_cost.csv"); % users

i = vs_x(:,1);
j = vs_x(:,2);

[fit_x, fit_y, slop, intercept] = regression(vs_x(:,1), vs_x(:,2));
m1 = slop
d1 = intercept

[fit_x, fit_y, slop, intercept] = regression(vs_y(:,1), vs_y(:,2));
m2 = slop
d2 = intercept

plot(vs_y(:,1), vs_y(:,2), '-o');
hold on;
plot(fit_x, fit_y, '-*');
grid on;
xlim([0,0.1]);
ylim([0,100]);
legend("Real measurements", "Fitted values");

saveas(gca, "./benchmarks/test_sharing_cost_reg.pdf");
