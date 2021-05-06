y = [100, 200, 400, 800];
r = [80, 160, 240];

%% cols:
cert = 1;
dece = 2;
ours = 3;

y_vs_enc = [13.59, 2.64, 0.048;
            25.47, 2.80, 0.043;
            49.43, 2.87, 0.041;
            75.36, 4.31, 0.072];

y_vs_dec = [3.23, 1.98, 0.038;
            3.44, 2.17, 0.038;
            3.22, 2.09, 0.040;
            3.35, 3.55, 0.061];

y_vs_storage = [ 6.695,  71.76,  40.192;
                13.195, 143.26,  80.336;
                26.195, 286.26, 160.624;
                52.195, 572.26, 302.624];


r_vs_enc = [96.36, 4.11, 0.081;
            87.87, 3.59, 0.077;
            75.36, 4.31, 0.072];

r_vs_dec = [3.32, 2.37, 0.079;
            3.23, 2.87, 0.075;
            3.35, 3.55, 0.061];

r_vs_storage = [52.195,  572.26, 321.184;
                52.195,  572.26, 311.904;
                52.195,  572.26, 302.624];

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
