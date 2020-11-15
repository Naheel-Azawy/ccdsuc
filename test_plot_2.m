function test_plot_2(xdata1, ydata1, xdata2, ydata2, xlabel1, xlabel2, ylabel0)
  %% Create the first axes
  hax1 = axes();

  %% First plot
  hplot1 = line(xdata1, ydata1);
    
  %% Create a transparent axes on top of the first one with it's xaxis on top
  %% and no ytick marks (or labels)
  hax2 = axes('Position', get(hax1, 'Position'), ...  % Copy position
              'XAxisLocation', 'top', ...             % Put the x axis on top
              'YAxisLocation', 'right', ...           % Doesn't really matter
              'Color', 'none', ...                    % Make it transparent
              'YTick', []);                           % Don't show markers on y axis
            
  %% Plot data with a different x-range here
  hplot2 = line(xdata2, ydata2, 'Color', 'r', 'Parent', hax2);

  %% Link the y limits and position together
  linkprop([hax1, hax2], {'ylim', 'Position'});

  %% Set limits
  maxy = max([max(ydata1), max(ydata2)]);
  ylim([0, maxy]);
  xlim(hax1, [0, max(xdata1)])
  xlim(hax2, [0, max(xdata2)])

  %% Draw some labels
  xlabel(hax1, xlabel1)
  xlabel(hax2, xlabel2)
  ylabel(hax1, ylabel0)
  legend([hplot1, hplot2], {xlabel1, xlabel2})
  grid on;
end
