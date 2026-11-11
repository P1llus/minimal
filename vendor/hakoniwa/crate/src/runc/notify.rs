use std::io::prelude::*;
use std::io::{PipeReader, PipeWriter};

use super::error::*;
use crate::Container;

pub(crate) fn notify_mainp_setup(
    container: &Container,
    mut reader: &PipeReader,
    mut writer: &PipeWriter,
) -> Result<()> {
    let mut operations = 0;
    if container.needs_mainp_setup_ugidmap() {
        operations |= crate::runc::SETUP_UGIDMAP;
    }
    if container.needs_mainp_setup_network() {
        operations |= crate::runc::SETUP_NETWORK;
    }
    if container.needs_mainp_setup_cgroups() {
        operations |= crate::runc::SETUP_CGROUPS;
    }

    if operations != 0 {
        let mut response = [0];
        writer.write_all(&[operations])?;
        reader.read_exact(&mut response)?;
    }

    Ok(())
}

pub(crate) fn notify_mainp_setup_success(mut writer: &PipeWriter) -> Result<()> {
    writer.write_all(&[crate::runc::SETUP_SUCCESS])?;
    Ok(())
}
