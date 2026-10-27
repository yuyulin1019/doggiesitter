# 毛孩保母時間

多位保母登記「哪天、幾點到幾點」有空，主人一眼看到誰有空。

- **登入**：大家開同一個網址 → 點自己的名字 → 輸入自己的 4 位數 PIN。手機會記住，下次直接進入；按「換人」可登出。
- **保母**：在月曆點選多天 → 選時段（上午／下午／晚上／整天／自訂）→ 一次登記。可在當日詳情取消自己的時段。
- **主人**：月曆上每天顯示各保母的顏色與時間，點某天看時間軸，可篩選單一保母。主人只能看、不能改。

## 為什麼保母不會改到別人的時段

1. **每人一組 PIN**：PIN 以加密雜湊存放，同一人連錯 5 次鎖 15 分鐘。登入成功後拿到一張隨機「通行證」（token），資料庫只存它的雜湊值，之後每個動作都用它認人。（GitHub Pages 只能放靜態網頁，沒辦法分辨誰是誰，所以身分檢查放在 Supabase。）
2. **瀏覽器碰不到資料表**：所有讀寫都經過資料庫函式（`calendar_add_slots`、`calendar_remove_slot` 等）。函式先用 token 認出「你是誰」，新增時一律寫入你的 id（網頁傳不進別人的 id），刪除時同時比對「時段 id＋你的 id」。
3. **保母只看得到自己的時段**；主人連結看得到全部但不能改。
4. **同一位保母的時段不能重疊**（資料庫層的限制）。不同保母之間互不影響。
5. **每次登記／取消／改名都有紀錄**，存在 `calendar_private.changes`（誰、用哪條連結、改了什麼）。
6. PIN 外流時，管理者重設 PIN 即可，該人所有裝置會一起被登出（見下方）。

## Stack

- 純 HTML／CSS／JavaScript（單一 `index.html`）
- Supabase Postgres（函式＋RLS，不開放匿名直接讀寫資料表）

## 設定 Supabase

1. 在 Supabase SQL Editor 執行 `supabase/setup.sql`（會建立 `佑宥`、`楚涵` 兩位保母和 `主人`）。
2. 新增保母：
   ```sql
   insert into public.members (display_name, role) values ('小米', 'sitter');
   ```
3. 設定或重設 PIN（**有設 PIN 的人才會出現在登入名單**；重設會讓這個人所有裝置登出）：
   ```sql
   select calendar_private.set_pin((select id from public.members where display_name = '小米'), '4 位數字');
   ```
4. 移除保母：`delete from public.members where display_name = '小米';`（他的時段會一起刪除）
5. 查異動紀錄：
   ```sql
   select changed_at, display_name, operation, available_on, after_data
   from calendar_private.changes order by changed_at desc limit 50;
   ```
6. `supabase-config.js` 放的是 publishable key，可以公開；**絕對不要**放 secret／service_role key。`calendar_private` schema 不要加進 Data API 的 exposed schemas。

## 本機試用

```sh
python3 -m http.server 8000
```

- `http://localhost:8000/?demo=owner`：主人畫面（假資料，不連資料庫）
- `http://localhost:8000/?demo=sitter`：保母畫面（假資料）
- `http://localhost:8000/`：連真的資料庫，選名字＋PIN 登入
