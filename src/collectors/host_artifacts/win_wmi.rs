//! Windows WMI 事件订阅采集：root\subscription 命名空间的
//! __EventFilter / __CommandLineEventConsumer / __FilterToConsumerBinding。
//! 任何 CommandLineEventConsumer 绑定都是高危持久化信号。

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;

use crate::collectors::command::{collect_text_command, CommandSpec};

const HEADER: &str = "class,name,data,detail\r\n";

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_text_command(
        "wmi_subscriptions",
        &layout.wmi_subscriptions,
        HEADER,
        &[wmi_commands()],
        errors,
        false,
    )
}

fn wmi_commands() -> CommandSpec {
    // 逐类查询 try/catch:部分系统对个别 WMI 类返回 0x80041010(类不受支持),
    // 单类失败只跳过该类继续采集其余;不再让整个脚本 Stop 把脚本文本灌进错误表。
    let script = r#"
$ErrorActionPreference = 'Continue'
$rows = New-Object System.Collections.Generic.List[object]
try { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
  $rows.Add([pscustomobject]@{ class='__EventFilter'; name=$_.Name; data=$_.Query; detail="language=$($_.QueryLanguage)" })
} } catch { }
try { Get-CimInstance -Namespace root\subscription -ClassName __CommandLineEventConsumer -ErrorAction Stop | ForEach-Object {
  $rows.Add([pscustomobject]@{ class='__CommandLineEventConsumer'; name=$_.Name; data=$_.CommandLineTemplate; detail="exe=$($_.ExecutablePath)" })
} } catch { }
try { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
  $rows.Add([pscustomobject]@{ class='__FilterToConsumerBinding'; name=$_.Filter; data=$_.Consumer; detail='' })
} } catch { }
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}
