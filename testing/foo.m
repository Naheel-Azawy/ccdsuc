vs_x = csvread("./benchmarks/test_sharing_N_vs_cost.csv"); % files
vs_y = csvread("./benchmarks/test_sharing_U_vs_cost.csv"); % users

function [slop, intercept] = regression(x, y)
  X = [ones(length(x), 1) x];
  theta = (pinv(X' * X)) * X' * y;
  intercept = theta(1);
  slop = theta(2);
end

[m1, d1] = regression(vs_x(:,1), vs_x(:,2))
[m2, d2] = regression(vs_y(:,1), vs_y(:,2))
