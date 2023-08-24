extern crate hexdump;
extern crate mpa_reader;

use mpa_reader::*;
use std::env;
use std::fs::File;
use std::io;

struct DumpMpaConsumer {
    frame_count: usize,
}
impl MpaConsumer for DumpMpaConsumer {
    fn new_config(
        &mut self,
        mpeg_version: MpegVersion,
        mpeg_layer: MpegLayer,
        protection: ProtectionIndicator,
        rate: BitRate,
        freq: SamplingFrequency,
        private_bit: u8,
        channel_mode: ChannelMode,
        copyright: Copyright,
        originality: Originality,
        emphasis: Emphasis,
    ) {
        println!("New MPA configuration found");
        println!(
            "{:?} {:?} {:?} {:?} {:?} private_bit={} {:?} {:?} {:?} {:?}",
            mpeg_version,
            mpeg_layer,
            protection,
            rate,
            freq,
            private_bit,
            channel_mode,
            copyright,
            originality,
            emphasis,
        );
    }
    fn payload(&mut self, header: &MpaHeader, buf: &[u8]) {
        println!("Audio Frame {:?}", header);
        hexdump::hexdump(buf);
        self.frame_count += 1;
    }
    fn error(&mut self, err: MpaParseError) {
        println!("Error: {:?}", err);
    }
}

fn run<R>(mut r: R) -> io::Result<()>
where
    R: io::Read,
    R: Sized,
{
    const LEN: usize = 1024 * 1024;
    let mut buf = [0u8; LEN];
    let mut byte_count = 0;
    let mut parser = MpaParser::new(DumpMpaConsumer { frame_count: 0 });
    loop {
        match r.read(&mut buf[..])? {
            0 => break,
            n => {
                let target = &mut buf[0..n];
                parser.push(target);
                byte_count += n;
            }
        };
    }
    println!(
        "Processed {} bytes, {} ADTS frames",
        byte_count, parser.consumer.frame_count
    );
    Ok(())
}

fn main() {
    let mut args = env::args();
    args.next();
    let name = args.next().unwrap();
    let f = File::open(&name).expect(&format!("file not found: {}", &name));
    run(f).expect(&format!("error reading {}", &name));
}
