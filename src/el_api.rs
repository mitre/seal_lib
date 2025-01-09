use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
/// Represents the messages an agent can send to the C2
pub enum AgentMessage {
    AgentInit(AgentInit),
    ResultMessage(ResultMessage),
    /// Sends the paw and listens for instructions
    Heartbeat(String),
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the messages the C2 server can send to an agent
pub enum C2Message {
    BeaconToAgent(BeaconToAgent),
    Instruction(Instruction),
    Wait
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the initial message an agent sends to a C2
///
/// <https://caldera.readthedocs.io/en/latest/How-to-Build-Agents.html#part-1>
pub struct AgentInit {
    /// The operating system
    pub platform: String,
    /// The hostname of the machine
    pub host: String,
    /// The username running the agent
    pub username: String,
    /// Unique identifier for the agent
    pub paw: String,
}


#[derive(Serialize, Deserialize, Debug)]
/// Agent identifier, instruction identifier, and CommandResults to be sent to the C2
pub struct ResultMessage {
    /// Unique identifier for the agent
    pub paw: String,
    /// Unique identifier for the instruction, used so EL can keep track of effects and responses
    pub id: String,
    /// Either the system output from running a command, or a file upload / download result
    pub result: ResultType,
}

#[derive(Serialize, Deserialize, Debug)]
/// Enum for what a result can be
pub enum ResultType {
    /// Command result
    CR(CommandResult),
    /// Instruction result
    IR(InstructionResult),
}

#[derive(Serialize, Deserialize, Debug)]
/// The system output from running a command
pub struct CommandResult {
    /// The output (or stdout) from running the instruction
    pub output: String,
    /// The error message (or stderr) from running the instruction
    pub stderr: String,
    /// The OS or process exit code from running the instruction. If unsure, put 0.
    pub exit_code: u32,
    /// The status message from running the instruction. If unsure, leave blank.
    pub status: String,
    /// The process identifier the instruction ran under. If unsure, put 0.
    pub pid: u32,
    /// Time since UNIX EPOCH in milliseconds
    pub timestamp: u128,
}

#[derive(Serialize, Deserialize, Debug)]
/// A success or fail result message, used particularly for file upload and download.
pub struct InstructionResult {
    /// Indicates if the instruction succeeded or not. True for success, false for failure.
    pub success: bool,
    /// An optional message describing why it failed.
    pub message: Option<String>,
    /// Time since UNIX EPOCH in milliseconds
    pub timestamp: u128,
}

#[derive(Serialize, Deserialize, Debug)]
/// Initial response from the C2 to the agent
pub struct BeaconToAgent {
    /// Unique identifier for the agent
    pub paw: String,
    /// Unique identifier for the instruction, used so EL can keep track of effects and responses
    pub id: String,
    /// The recommended number of seconds to sleep before sending the next beacon
    pub sleep: u64,
    /// The recommended number of seconds  to wait before killing the agent,
    /// once the server is unreachable (0 means infinite)
    ///
    /// NOT IMPLEMENTED
    pub watchdog: u64,
    /// A list of commands (NOT the Instructions type)
    pub instructions: Vec<String>
}

/// <https://caldera.readthedocs.io/en/latest/How-to-Build-Agents.html#part-2>
#[derive(Serialize, Deserialize, Debug)]
pub struct Instruction {
    /// Unique identifier for the instruction, used so EL can keep track of effects and responses
    pub id: String,
    /// Pause time after running the instruction, in ms
    pub sleep: u64,
    /// The executor to run the command under.
    /// If left blank, uses the default for the operating system.
    pub executor: Option<String>,
    /// Command to run.
    /// If left blank, doesn't run anything.
    pub command: Option<String>,
    /// How long to let the command run before timing it out, in ms
    pub timeout: u64,
    /// A payload file name which must be downloaded before running the command, if applicable
    pub payload: Option<String>,
    /// A list of file names that the agent must upload to the C2 server after running the command.
    pub uploads: Option<Vec<String>>,
}
