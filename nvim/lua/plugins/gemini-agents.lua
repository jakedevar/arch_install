return {
  {
    -- Point to your local working directory
    dir = "/home/jakedevar/gemini-cli/agents.nvim",
    name = "agents.nvim",

    -- Load only when these commands are used
    cmd = { "AgentsChat", "AgentsStop" },

    -- Dependencies
    dependencies = { "nvim-telescope/telescope.nvim" },

    -- Setup configuration
    opts = {
      -- Default is "gemini". Uncomment below to use your dev build:
      -- cmd = { "node", "/home/jakedevar/gemini-cli/bundle/gemini.js" },
    },

    config = function(_, opts)
      require("agents").setup(opts)
    end,

    -- Keymaps (Optional)
    keys = {
      { "<leader>ac", "<cmd>AgentsChat<cr>", desc = "Gemini Agents Chat" },
    },
  },
}
