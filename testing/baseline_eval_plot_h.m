baseline_eval_data;

figure;

subplot(2, 3, 1);
plot(y, y_vs_enc(:,cert), 'b');
hold on;
plot(y, y_vs_enc(:,dece), 'r');
hold on;
plot(y, y_vs_enc(:,ours), 'g');
grid on;
title("(a)");
xlabel("y"); ylabel("Enc. (ms)");
legend("[6]", "[4]", "Ours");

subplot(2, 3, 2);
plot(y, y_vs_dec(:,cert), 'b');
hold on;
plot(y, y_vs_dec(:,dece), 'r');
hold on;
plot(y, y_vs_dec(:,ours), 'g');
grid on;
title("(c)");
xlabel("y"); ylabel("Dec. (ms)");
legend("[6]", "[4]", "Ours");

subplot(2, 3, 3);
plot(y, y_vs_storage(:,cert), 'b');
hold on;
plot(y, y_vs_storage(:,dece), 'r');
hold on;
plot(y, y_vs_storage(:,ours), 'g');
grid on;
title("(e)");
xlabel("y"); ylabel("Storage (KB)");
legend("[6]", "[4]", "Ours");


subplot(2, 3, 4);
plot(r, r_vs_enc(:,cert), 'b');
hold on;
plot(r, r_vs_enc(:,dece), 'r');
hold on;
plot(r, r_vs_enc(:,ours), 'g');
grid on;
title("(b)");
xlabel("r"); ylabel("Enc. (ms)");
legend("[6]", "[4]", "Ours");

subplot(2, 3, 5);
plot(r, r_vs_dec(:,cert), 'b');
hold on;
plot(r, r_vs_dec(:,dece), 'r');
hold on;
plot(r, r_vs_dec(:,ours), 'g');
grid on;
title("(d)");
xlabel("r"); ylabel("Dec. (ms)");
legend("[6]", "[4]", "Ours");

subplot(2, 3, 6);
plot(r, r_vs_storage(:,cert), 'b');
hold on;
plot(r, r_vs_storage(:,dece), 'r');
hold on;
plot(r, r_vs_storage(:,ours), 'g');
grid on;
title("(f)");
xlabel("r"); ylabel("Storage (KB)");
legend("[6]", "[4]", "Ours");

%set(gcf, 'papersize', [24,16]);
saveas(gcf, "./benchmarks/test_eval_data.svg");
