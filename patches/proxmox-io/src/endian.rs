/// Trait for converting values between byte orderings.
///
/// Replaces the abandoned `endian_trait` crate (RUSTSEC-2021-0039).
pub trait Endian {
    fn to_le(self) -> Self;
    fn to_be(self) -> Self;
    fn from_le(self) -> Self;
    fn from_be(self) -> Self;
}

macro_rules! impl_endian_int {
    ($($ty:ty),*) => { $(
        impl Endian for $ty {
            #[inline] fn to_le(self) -> Self { <$ty>::to_le(self) }
            #[inline] fn to_be(self) -> Self { <$ty>::to_be(self) }
            #[inline] fn from_le(self) -> Self { <$ty>::from_le(self) }
            #[inline] fn from_be(self) -> Self { <$ty>::from_be(self) }
        }
    )* };
}

impl_endian_int!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);
