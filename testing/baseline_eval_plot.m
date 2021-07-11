baseline_eval_data;

figure;

poffset = 2;

subplot(4, 2, 1 + poffset);
plot(y, y_vs_enc(:,cert), 'b');
hold on;
plot(y, y_vs_enc(:,dece), 'r');
hold on;
plot(y, y_vs_enc(:,ours), 'g');
grid on;
title("(a)");
xlabel("Number of users (y)"); ylabel("Enc. (ms)");

subplot(4, 2, 3 + poffset);
plot(y, y_vs_dec(:,cert), 'b');
hold on;
plot(y, y_vs_dec(:,dece), 'r');
hold on;
plot(y, y_vs_dec(:,ours), 'g');
grid on;
title("(c)");
xlabel("Number of users (y)"); ylabel("Dec. (ms)");

subplot(4, 2, 5 + poffset);
plot(y, y_vs_storage(:,cert), 'b');
hold on;
plot(y, y_vs_storage(:,dece), 'r');
hold on;
plot(y, y_vs_storage(:,ours), 'g');
grid on;
title("(e)");
xlabel("Number of users (y)"); ylabel("Storage (KB)");


subplot(4, 2, 2 + poffset);
plot(r, r_vs_enc(:,cert), 'b');
hold on;
plot(r, r_vs_enc(:,dece), 'r');
hold on;
plot(r, r_vs_enc(:,ours), 'g');
grid on;
title("(b)");
xlabel("Number of revoked users (r)"); ylabel("Enc. (ms)");

subplot(4, 2, 4 + poffset);
plot(r, r_vs_dec(:,cert), 'b');
hold on;
plot(r, r_vs_dec(:,dece), 'r');
hold on;
plot(r, r_vs_dec(:,ours), 'g');
grid on;
title("(d)");
xlabel("Number of revoked users (r)"); ylabel("Dec. (ms)");

subplot(4, 2, 6 + poffset);
h1 = plot(r, r_vs_storage(:,cert), 'b');
hold on;
h2 = plot(r, r_vs_storage(:,dece), 'r');
hold on;
h3 = plot(r, r_vs_storage(:,ours), 'g');
grid on;
title("(f)");
xlabel("Number of revoked users (r)"); ylabel("Storage (KB)");

hl = subplot(4, 2, [1 2]);
lgd = legend(hl, [h1;h2;h3], 'Certificate-based [6]', 'Decentralized [4]', 'Ours');
pos = get(lgd, 'position');     % Getting its position
%% pos(2) -= .1 * pos(2);
%% set(lgd, 'position', pos);     % Adjusting legend's position
axis(hl, 'off');               % Turning its axis off

%set(gcf, 'papersize', [24,16]);
saveas(gcf, "./benchmarks/test_eval_data.pdf");
