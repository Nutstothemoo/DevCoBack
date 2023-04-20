BEGIN;

TRUNCATE "user", skill, post, feed, feed_has_user, user_has_skill RESTART IDENTITY CASCADE;

INSERT INTO "user" (firstname, lastname, username, email, password, image_path, role)
VALUES ('jean', 'david', 'gogodu93', 'jeandavid93@gmail.com', 'xxxxizjodjziojz', '/public/asset.png', 'member');

INSERT INTO skill (name, level)
VALUES ('debutant', 3);

INSERT INTO post (title, content, user_id, "like")
VALUES ('React in 1 minute', 'blablabla', 1, 0);

INSERT INTO feed (name, url)
VALUES ('Dev.to', 'Dev.to/feed');

INSERT INTO feed_has_user (feed_id, user_id)
VALUES (1, 1);

INSERT INTO user_has_skill (skill_id, user_id)
VALUES (1, 1);

COMMIT;
