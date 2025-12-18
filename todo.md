# ChatLog MCP 扩展方案 TODO

## 1. 媒体内容感知服务 (Media Perception)
- [x] **get_media_content (Tool)**: 
  - **功能**: 根据消息 ID 获取解码后的媒体文件（图片自动解密、语音转 MP3）。
  - **用法**: `get_media_content(talker="ID", message_id=123456)`
- [x] **ocr_image_message (Tool)**: 
  - **功能**: 对图片消息进行 OCR 解析（由模型视觉能力驱动）。
  - **用法**: `ocr_image_message(talker="ID", message_id=123456)`

## 2. 实时消息通知与 Webhook 推送 (Real-time Interaction)
- [x] **subscribe_new_messages (Tool)**: 
  - **功能**: 订阅实时消息流。订阅后，当有新消息时，系统会自动推送到指定的 Webhook 地址。
  - **要求**: 必须提供订阅目标 (talker) 和推送地址 (webhook_url)。
  - **用法**: `subscribe_new_messages(talker="ID", webhook_url="http://...")`
- [x] **unsubscribe_new_messages (Tool)**:
  - **功能**: 取消订阅实时消息流。
  - **用法**: `unsubscribe_new_messages(talker="ID")`
- [x] **get_active_subscriptions (Tool)**:
  - **功能**: 获取当前活跃的订阅列表及推送地址。
  - **用法**: `get_active_subscriptions()`
- [x] **订阅持久化**: 订阅信息自动保存至本地配置文件，重启后自动恢复。
- [x] **推送状态监控**: TUI 界面可实时查看每个订阅的推送成功/失败状态及错误原因。
- [x] **send_webhook_notification (Tool)**: 
  - **功能**: 当模型分析完记录后，触发外部分析报告 Hook。

## 3. 数据分析与社交画像 (Social Insights)
- [x] **analyze_chat_activity (Tool)**: 
  - **功能**: 统计发言频率、活跃时段（带柱状图可视化模拟）。
  - **用法**: `analyze_chat_activity(talker="ID", time="2023-04-01~2023-04-30")`
- [x] **get_user_profile (Tool)**: 
  - **功能**: 获取备注、微信号、群成员及群主等背景信息。
  - **用法**: `get_user_profile(key="ID或名称")`

## 4. 增强型提示词模板 (Prompts)
- [x] **chat_summary_daily (Prompt)**: 每日聊天摘要。参数: `date`, `talker`。
- [x] **conflict_detector (Prompt)**: 情绪与冲突检测。参数: `talker`。
- [x] **relationship_milestones (Prompt)**: 关系里程碑回顾。参数: `talker`。

## 5. 跨应用检索 (Cross-app Retrieval)
- [x] **search_shared_files (Tool)**: 
  - **功能**: 专门搜索聊天记录中发送的文件元数据。
  - **用法**: `search_shared_files(talker="ID", keyword="报告")`

## 6. 系统优化 (Infrastructure)
- [x] **唯一消息 ID 系统**: 引入 `(timestamp * 1000000 + local_id)` 算法，解决多媒体消息 ID 冲突问题。
- [x] **多格式输出适配**: 文本、CSV、JSON 均已支持显示唯一 `MessageID`。