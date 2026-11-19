CREATE TABLE records (id INTEGER PRIMARY KEY, name TEXT, type TEXT, content TEXT, ttl INTEGER, disabled BOOLEAN);
INSERT INTO records VALUES
  (1, 'server.split.test', 'A', '192.0.2.99', 60, 0),
  (2, 'retired.split.test', 'CNAME', 'server.split.test.', 60, 0),
  (3, 'laptop.split.test', 'A', '192.0.2.31', 60, 0),
  (4, 'desktop.split.test', 'AAAA', 'fd00:abcd::31', 60, 0),
  (5, 'power.split.test', 'A', '192.0.2.44', 60, 0),
  (6, 'network.split.test', 'A', '192.0.2.51', 60, 0),
  (7, 'disabled.split.test', 'A', '192.0.2.60', 60, 1);
