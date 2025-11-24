use generic_array::{ArrayLength, GenericArray};

pub struct Key<N: ArrayLength<u8>> {
    
    data: GenericArray<u8, N>
}

impl<N: ArrayLength<u8>> Key<N> {
    pub fn new(data: GenericArray<u8, N>) -> Self {
        Self {
            data
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}