use std::time::{Duration, Instant};

pub struct Timer {
    start: Instant,
    label: &'static str,
}

impl Timer {
    pub fn start(label: &'static str) -> Self {
        Timer { start: Instant::now(), label }
    }

    pub fn stop(self) -> Duration {
        let elapsed = self.start.elapsed();
        println!("[telemetry] {} took {:.3}ms", self.label, elapsed.as_secs_f64() * 1000.0);
        elapsed
    }
}
