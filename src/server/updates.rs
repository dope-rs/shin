use super::*;

pub(super) trait Updates {
    fn handle_key_update<S: EventSink + ?Sized>(
        &mut self,
        ku: KeyUpdate,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>;
}
impl<C: Clock> Updates for Server<C> {
    fn handle_key_update<S: EventSink + ?Sized>(
        &mut self,
        ku: KeyUpdate,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        if !self.key_updates.consume() {
            return Err(Error::UnexpectedMessage.into());
        }
        let c_ap = self.c_ap_traffic.ok_or(Error::UnexpectedMessage)?;
        let new_c_ap = Hkdf::new(self.hash_alg())
            .traffic_update(&c_ap)?
            .to_digest();
        self.c_ap_traffic = Some(new_c_ap);
        EventContext::emit(
            events,
            self.negotiated_suite,
            Event::KeyUpdate {
                direction: KeyDirection::Read,
                secret: new_c_ap,
            },
        )?;

        if ku.request_update == 1 {
            let reply = KeyUpdate { request_update: 0 };
            let bytes = reply.encode_framed();
            EventContext::emit(
                events,
                self.negotiated_suite,
                Event::Send {
                    epoch: Epoch::Application,
                    data: &bytes,
                },
            )?;
            let s_ap = self.s_ap_traffic.ok_or(Error::UnexpectedMessage)?;
            let new_s_ap = Hkdf::new(self.hash_alg())
                .traffic_update(&s_ap)?
                .to_digest();
            self.s_ap_traffic = Some(new_s_ap);
            EventContext::emit(
                events,
                self.negotiated_suite,
                Event::KeyUpdate {
                    direction: KeyDirection::Write,
                    secret: new_s_ap,
                },
            )?;
        }
        Ok(())
    }
}
