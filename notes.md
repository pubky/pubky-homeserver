3cjussse73qny9wiogkk5iu9qkw784k8t7dxbj819hj6btg3todo

# 1. provision a demo user
curl -s -X POST "https://<host>/generate_demo_user" -H "X-Admin-Password: $PW" | tee demo.json

# 2. native client still mounts (must show `dav: 1,2,3`)
curl -i -X OPTIONS "https://<host>/dav/<key>/" -u "<key>:<token>" | grep -i '^dav:'

# 3. browser clients allowed (must show allow-origin, and NO allow-credentials)
curl -i -X OPTIONS "https://homeserver-tomos.space/dav/3cjussse73qny9wiogkk5iu9qkw784k8t7dxbj819hj6btg3todo/" \
  -H "Origin: https://example.test" -H "Access-Control-Request-Method: PROPFIND" | grep -i access-control
