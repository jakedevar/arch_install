-- -- Keymaps are automatically loaded on the VeryLazy event
-- Default keymaps that are always set: https://github.com/LazyVim/LazyVim/blob/main/lua/lazyvim/config/keymaps.lua
-- Add any additional keymaps here

-- -- LSP keymaps
-- window resizing
vim.keymap.set("n", "<C-S-Up>", "<cmd>resize +4<cr>", { desc = "Increase Window Height" })
vim.keymap.set("n", "<C-S-Down>", "<cmd>resize -4<cr>", { desc = "Decrease Window Height" })
vim.keymap.set("n", "<C-S-Left>", "<cmd>vertical resize -4<cr>", { desc = "Decrease Window Width" })
vim.keymap.set("n", "<C-S-h>", "<cmd>vertical resize -4<cr>", { desc = "Decrease Window Width" })
vim.keymap.set("n", "<C-S-Right>", "<cmd>vertical resize +4<cr>", { desc = "Increase Window Width" })
vim.keymap.set("n", "<C-S-l>", "<cmd>vertical resize +4<cr>", { desc = "Increase Window Width" })

-- delete windows keymaps
vim.keymap.set("n", "<leader>qq", "<C-W>c", { desc = "Delete Window", remap = true })
vim.keymap.set("n", "<leader>qa", "<cmd>qa<cr>", { desc = "Quit All" })

-- Terminal Mappings
vim.keymap.set("n", "<leader>ft", function()
  Snacks.terminal()
end, { desc = "Terminal (cwd)" })
vim.keymap.set("n", "<leader>fT", function()
  Snacks.terminal(nil, { cwd = LazyVim.root() })
end, { desc = "Terminal (Root Dir)" })
vim.keymap.set("n", "<c-\\>", function()
  Snacks.terminal()
end, { desc = "Terminal (cwd)" })
vim.keymap.set("t", "<C-\\>", "<cmd>close<cr>", { desc = "Hide Terminal" })
vim.keymap.set("t", "<c-_>", "<cmd>close<cr>", { desc = "which_key_ignore" })

-- other remaps
vim.keymap.set("n", "<C-b>", "<C-v>", { desc = "remap visual block mode" })
vim.keymap.set("n", "<leader>be", "<cmd>BufferLinePickClose<CR>", { desc = "Pick and close a buffer" })
vim.keymap.set("n", "<leader>cc", "<cmd>CopilotChatToggle<CR>", { desc = "Toggles the copilot chat" })

-- fzf
--     keys = {
-- { "<c-j>", "<c-j>", ft = "fzf", mode = "t", nowait = true },
-- { "<c-k>", "<c-k>", ft = "fzf", mode = "t", nowait = true },
-- {
--   "<leader>,",
--   "<cmd>FzfLua buffers sort_mru=true sort_lastused=true<cr>",
--   desc = "Switch Buffer",
-- },
-- { "<leader>/", LazyVim.pick("live_grep", { root = false }), desc = "Grep (cwd)" },
-- { "<leader>:", "<cmd>FzfLua command_history<cr>", desc = "Command History" },
-- { "<leader><space>", LazyVim.pick("files"), desc = "Find Files (cwd)" },
-- -- find
-- { "<leader>fb", "<cmd>FzfLua buffers sort_mru=true sort_lastused=true<cr>", desc = "Buffers" },
-- { "<leader>fc", LazyVim.pick.config_files(), desc = "Find Config File" },
-- { "<leader>ff", LazyVim.pick("files"), desc = "Find Files (Root Dir)" },
-- { "<leader>fF", LazyVim.pick("files", { root = false }), desc = "Find Files (cwd)" },
--  telescpe
--         {
-- "nvim-telescope/telescope.nvim",

--       { "<leader>sG", LazyVim.pick("live_grep"), desc = "Grep (Root Dir)" },
-- { "<leader>sg", LazyVim.pick("live_grep", { root = false }), desc = "Grep (cwd)" },
--
