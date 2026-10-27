# 毛孩散步日曆

多人共用的保母可服務日期月曆。主人登入後可查看所有保母空檔；保母登入後可登記或取消自己的日期。

## Stack

- Static HTML, CSS, and JavaScript
- Supabase Auth (email magic link)
- Supabase Postgres with row level security and Realtime

## Supabase setup

1. Open `supabase/setup.sql` in the Supabase SQL Editor and run it.
2. In Supabase Authentication, invite each owner and sitter by email.
3. After each person accepts the invite, copy their user UUID from Authentication → Users, then add their access row in the SQL Editor:

   ```sql
   insert into public.members (id, display_name, role)
   values ('AUTH_USER_UUID', '顯示名稱', 'owner');
   ```

   Use `sitter` for sitters. Only add people who should access this calendar. The browser app cannot grant access or change account roles.
4. Add the local and deployed URLs to Authentication → URL Configuration → Redirect URLs. For local use, allow `http://localhost:8000/**`; for GitHub Pages, allow `https://GITHUB_USERNAME.github.io/REPOSITORY_NAME/**`.
5. The project URL and publishable key are in `supabase-config.js`. The publishable key is safe in a browser app when RLS is enabled. Never add a secret or service-role key.

## Run locally

Serve the folder over HTTP (the email sign-in flow does not work from `file://`):

```sh
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## Access rules

- Signed-in members can read the member list and shared availability.
- Owners are read-only.
- Sitters can add and remove only their own availability rows.
- Only a project administrator can invite members and assign `owner` or `sitter` roles.
- `supabase/setup.sql` grants no anonymous access. The GitHub repository may be public without exposing the calendar data.
