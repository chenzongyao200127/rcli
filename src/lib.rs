mod cli;
mod process;
mod utils;

pub use cli::*;
pub use process::*;
pub use utils::*;

#[allow(async_fn_in_trait)]
pub trait CmdExcutor {
    async fn execute(self) -> anyhow::Result<()>;
}
