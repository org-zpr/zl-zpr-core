@0xdd33f90089b3556f;

interface CmdLineInter {
    echo                 @0 () -> ();
    resetCounters        @1 () -> ();
    counters             @2 () -> (counts: Counters);
    setCaptureFile       @3 (captureFile: CaptureFile) -> (result: SuccessOrError);
    closeCaptureFile     @4 () -> ();
    flushCaptureFile     @5 () -> ();
    setCaptureProgram    @6 (program: Program) -> (result: SuccessOrError);
    deleteCaptureProgram @7 () -> ();
    perfSample           @8 (duration_secs: UInt64, frequency_per_sec: UInt64) -> (result: Text); # Currently unsupported in PH
    showLinkSummary      @9 () -> (summary: List(Text));
    showLink             @10 (id: UInt32) -> (result: Text);
    configureLink        @11 (id: UInt32) -> (); # Currently unsupported in PH
    startLink            @12 (id: UInt32, authAgent: AuthAgent) -> (result: SuccessOrError); # authAgent is optional (null): a link started without one is device-only
    stopLink             @13 (id: UInt32) -> (result: SuccessOrError);
    resetLink            @14 (id: UInt32) -> ();
    changeLogging        @15 (logs: List(Log)) -> (result: LogsApplied);
    getNodeInfo          @16 () -> (result: SuccessOrError);
    getTunInfo           @17 () -> (result: SuccessOrError, info: TunInfo); # zipline#202: `ph-cli tun`
    # zl-zipline#233: a Zode's own login. `login` registers authAgent for
    # this connection and returns when the login finishes; its error text is
    # the AuthFailureReason Debug spelling. All three refuse on an adapter.
    login                @18 (authAgent: AuthAgent) -> (result: SuccessOrError);
    logout               @19 () -> (result: SuccessOrError);
    showLogin            @20 () -> (result: Text);
}

# The TUN interface ph opened (zipline#202). `zprAddrs` lists only the
# local ZPR addresses ph confirmed on that interface: empty on an adapter
# before its address is granted, and an address the platform cannot
# inspect is left out rather than guessed.
struct TunInfo {
    ifName   @0 :Text;
    zprAddrs @1 :List(IpAddr);
}

interface CaptureFile {
    # Passed to setCaptureFile by the controller (ph-cli). ph calls get_fd
    # and receives the capture file's descriptor as SCM_RIGHTS ancillary
    # data over the fd-passing (capnp-ancillary) transport (zipline#142).
}

# Provided by ph-cli (or another controller); called by ph when a credential
# requiring a user session is needed (zipline#13).
# `interactive = false` means "satisfy from a stored refresh token or fail";
# the agent must never open a browser on a non-interactive request.
interface AuthAgent {
    getOidcCredential @0 (issuer :Text, clientId :Text, clientSecret :Text, scopes :List(Text),
                          allowOfflineAccess :Bool, nonce :Text, interactive :Bool)
                      -> (result :SuccessOrError, idToken :Text);
}

struct SuccessOrError {
    union {
        success @0 :SuccessValue;
        error   @1 :ErrorValue;
    }
}

struct SuccessValue {
    none @0 :Void;
    sockAddr @1 :SockAddr;
}

struct ErrorValue {
    txt @0 :Text;
}

struct LogsApplied {
    applied @0 :List(Text);
    ignored @1 :List(Text);
}

struct Counter {
    name @0 :Text;
    val  @1 :UInt64;
}

struct CounterGroup {
    id       @0 :UInt32;
    counters @1 :List(Counter);
}

struct Counters {
    management     @0 :CounterGroup;
    fastpaths      @1 :List(CounterGroup);
    uptimeSec      @2 :UInt64;
    uptimeSubsecMs @3 :UInt32;
}

struct BpfInsn {
    code @0 :UInt16;
    jt   @1 :UInt8;
    jf   @2 :UInt8;
    k    @3 :UInt32;
}

struct Log {
    level  @0 :Text;
    target @1 :Text;
}

struct Program {
    bpfProg @0 :List(BpfInsn);
}

struct IpAddr {
  union {
    v4 @0 :Data;
    v6 @1 :Data;
  }
}

struct SockAddr {
  addr @0 :IpAddr;
  port @1 :UInt16;
}