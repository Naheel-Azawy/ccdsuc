figure;

range = 1:200;
speed_sharing    = csvread("./benchmarks/test_sharing_speed.csv")(range,:);
speed_no_sharing = csvread("./benchmarks/test_no_sharing_speed.csv")(range,:);

%% Key generation
diff = [];
for i = 1:size(speed_sharing)(1)
  diff = [diff, abs(speed_sharing(i, 2) - speed_no_sharing(i, 2))];
end
speed_difference_avg = mean(diff)
speed_difference_var = var(diff)

d = speed_no_sharing;
d(:,1) /= 1e+6;
p = plot(d(:,1), d(:,2));
hold on;
p = plot(d(:,1), d(:,3));
grid on;
ylim([0, max(d(:,2))])
xlabel("Size in megabytes");
ylabel("Time in milliseconds");
legend("Encryption",
       "Decryption");

saveas(p, "./benchmarks/test_sharing_speed.png");
