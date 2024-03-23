use anyhow::Result;

fn main() -> Result<()> {
    let args = makesksa::args::parse_args()?;

    makesksa::build(args)
}
