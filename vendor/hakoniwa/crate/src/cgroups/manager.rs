use libcgroups::common::{
    AnyCgroupManager, CgroupConfig, CgroupManager, ControllerOpt as CgroupControllerOpt,
    create_cgroup_manager,
};
use nix::unistd::Pid;
use std::path::PathBuf;

use super::{Resources, error::*};

pub(crate) struct Manager {
    manager: AnyCgroupManager,
}

impl Manager {
    pub(crate) fn new(id: &str) -> Result<Self> {
        let manager = create_cgroup_manager(CgroupConfig {
            cgroup_path: PathBuf::from(format!("hakoniwa.slice:hakoniwa:{id}")),
            systemd_cgroup: true,
            container_name: id.to_string(),
        })?;
        Ok(Self { manager })
    }

    pub(crate) fn apply(&self, task: Pid, resources: &Resources) -> Result<()> {
        let opts = CgroupControllerOpt {
            resources: &resources.build()?,
            disable_oom_killer: false,
            oom_score_adj: None,
            freezer_state: None,
        };
        self.manager.add_task(task)?;
        self.manager.apply(&opts)?;
        Ok(())
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        _ = self.manager.remove();
    }
}
