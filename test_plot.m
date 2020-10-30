
system("python3 test.py benchmark");

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

figure;
speed_sharing    = csvread("./benchmarks/test_sharing_speed.csv");
speed_no_sharing = csvread("./benchmarks/test_no_sharing_speed.csv");

subplot(2, 1, 1);
d = speed_sharing;
p = plot(d(:,1), d(:,2));
hold on;
d = speed_no_sharing;
p = plot(d(:,1), d(:,2));
grid on;
xlabel("Size in bytes");
ylabel("Encryption time in milliseconds");
legend("Sharing enabled",
       "Sharing disabled");

subplot(2, 1, 2);
d = speed_sharing;
p = plot(d(:,1), d(:,3));
hold on;
d = speed_no_sharing;
p = plot(d(:,1), d(:,3));
grid on;
xlabel("Size in bytes");
ylabel("Decryption time in milliseconds");
legend("Sharing enabled",
       "Sharing disabled");

saveas(p, "./benchmarks/test_sharing_speed.png");

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

figure;
d = csvread("./benchmarks/test_sharing_revocation_speed_vs_size.csv");
subplot(2, 1, 1);
p = plot(d(:,1), d(:,2));
xlabel("Size of the revoked file in bytes");
ylabel("Revocation time in milliseconds");
grid on;

subplot(2, 1, 2);
d = csvread("./benchmarks/test_sharing_revocation_speed_vs_U.csv");
p = plot(d(:,1), d(:,2));
xlabel("Number of users the file is shared with");
ylabel("Revocation time in milliseconds");
grid on;

saveas(p, "./benchmarks/test_sharing_revocation.png");

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

diff = [];
for i = 1:size(speed_sharing)(1)
  diff = [diff, abs(speed_sharing(i, 2) - speed_no_sharing(i, 2))];
end

speed_difference_avg = mean(diff)
speed_difference_var = var(diff)

waitfor(p);
