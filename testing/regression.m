function [fit_x, fit_y, slop, intercept] = regression(x, y)
  X = [ones(length(x), 1) x];
  theta = (pinv(X' * X)) * X' * y;
  intercept = theta(1);
  slop = theta(2);
  fit_x = X(:,2);
  fit_y = X * theta;
end
