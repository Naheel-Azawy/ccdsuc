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

diff = [];
for i = 1:size(speed_sharing)(1)
  diff = [diff, abs(speed_sharing(i, 2) - speed_no_sharing(i, 2))];
end

speed_difference_avg = mean(diff)
speed_difference_var = var(diff)

waitfor(p);
