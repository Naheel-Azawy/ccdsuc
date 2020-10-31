figure;

rev_sizes = csvread("./benchmarks/test_sharing_revocation_speed_vs_size.csv");
rev_users = csvread("./benchmarks/test_sharing_revocation_speed_vs_U.csv");

% Data
xdata1 = rev_sizes(:,1);
ydata1 = rev_sizes(:,2);
xdata2 = rev_users(:,1);
ydata2 = rev_users(:,2);

% Create the first axes
hax1 = axes();

% First plot
hplot1 = line(xdata1, ydata1);
    
% Create a transparent axes on top of the first one with it's xaxis on top
% and no ytick marks (or labels)
hax2 = axes('Position', get(hax1, 'Position'), ...  % Copy position
            'XAxisLocation', 'top', ...             % Put the x axis on top
            'YAxisLocation', 'right', ...           % Doesn't really matter
            'Color', 'none', ...                    % Make it transparent
            'YTick', []);                           % Don't show markers on y axis
            
% Plot data with a different x-range here
hplot2 = line(xdata2, ydata2, 'Color', 'r', 'Parent', hax2);

% Link the y limits and position together
linkprop([hax1, hax2], {'ylim', 'Position'});

maxy = max([max(ydata1), max(ydata2)]);
ylim([0, maxy]);

% Draw some labels
xlabel(hax1, 'Size of the revoked file in bytes')
xlabel(hax2, 'Number of users the file is shared with')
ylabel(hax1, 'Revocation time in milliseconds')
legend([hplot1, hplot2], ...
       {'Size of the revoked file in bytes', ...
        'Number of users the file is shared with'})
grid on;

saveas(gca, "./benchmarks/test_sharing_revocation.png");

waitfor(gca);
