//! Everything necessary for dynamic typing in the context of Type
//! Language.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;

use erased_serde::{self, Serialize as ErasedSerialize, Deserializer as ErasedDeserializer};
use serde::ser::{Serialize, Serializer};
use serde::de::{self, DeserializeOwned, DeserializeSeed, Deserializer, Error as DeError};
use serde_mtproto::{self, Identifiable, MtProtoSized};

use crate::error::{self, ErrorKind};


/// \[**IMPLEMENTATION DETAIL**]
/// Helper trait to implement Clone for trait objects.
///
/// Idea taken from:
///
/// * https://users.rust-lang.org/t/solved-is-it-possible-to-clone-a-boxed-trait-object/1714
/// * https://stackoverflow.com/questions/30353462/how-to-clone-a-struct-storing-a-trait-object
#[doc(hidden)]
pub trait TLObjectCloneToBox {
    fn clone_to_box(&self) -> Box<dyn TLObject>;
}

impl<T: Clone + TLObject + 'static> TLObjectCloneToBox for T {
    fn clone_to_box(&self) -> Box<dyn TLObject> {
        Box::new(self.clone())
    }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectType { Type, Function }

/// For any object type of which is representable in Type Language.
pub trait TLObject: Any + ErasedSerialize + Identifiable + MtProtoSized + TLObjectCloneToBox {
    fn object_type() -> ObjectType where Self: Sized;

    fn as_any(&self) -> &dyn Any where Self: Sized { self }
    fn as_box_any(self: Box<Self>) -> Box<dyn Any> where Self: Sized { self }
}

// TLObject impls

impl Serialize for dyn TLObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        erased_serde::serialize(self, serializer)
    }
}

impl fmt::Debug for dyn TLObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TLObject [trait object]")
    }
}

// &TLObject impls

impl<'a> Identifiable for &'a dyn TLObject {
    fn all_type_ids() -> &'static [u32] {
        panic!("Cannot use static methods on trait objects")
    }

    fn all_enum_variant_names() -> Option<&'static [&'static str]> {
        panic!("Cannot use static methods on trait objects")
    }

    fn type_id(&self) -> u32 {
        Identifiable::type_id(&**self)
    }

    fn enum_variant_id(&self) -> Option<&'static str> {
        Identifiable::enum_variant_id(&**self)
    }
}

// Box<TLObject> impls

impl Clone for Box<dyn TLObject> {
    fn clone(&self) -> Box<dyn TLObject> {
        self.clone_to_box()
    }
}

impl Identifiable for Box<dyn TLObject> {
    fn all_type_ids() -> &'static [u32] {
        panic!("Cannot use static methods on trait objects")
    }

    fn all_enum_variant_names() -> Option<&'static [&'static str]> {
        panic!("Cannot use static methods on trait objects")
    }

    fn type_id(&self) -> u32 {
        Identifiable::type_id(&**self)
    }

    fn enum_variant_id(&self) -> Option<&'static str> {
        Identifiable::enum_variant_id(&**self)
    }
}

// impl TLObject for external types

impl TLObject for bool {
    fn object_type() -> ObjectType {
        ObjectType::Type
    }
}

impl TLObject for i32 {
    fn object_type() -> ObjectType {
        ObjectType::Type
    }
}

impl TLObject for i64 {
    fn object_type() -> ObjectType {
        ObjectType::Type
    }
}

impl<T: Clone + Serialize + TLObject> TLObject for serde_mtproto::Boxed<T> {
    fn object_type() -> ObjectType {
        T::object_type()
    }
}


impl<T: Clone + Serialize + TLObject> TLObject for Vec<T> {
    fn object_type() -> ObjectType {
        T::object_type()
    }
}


pub(crate) type TLConstructorType = Box<dyn Fn(&mut dyn ErasedDeserializer<'_>) -> Result<Box<dyn TLObject>, erased_serde::Error>>;

/// A single TL constructor body (i.e. without its id).
pub struct TLConstructor(TLConstructorType);

impl fmt::Debug for TLConstructor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct DummyForDebug;

        impl fmt::Debug for DummyForDebug {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("TL constructor [boxed closure]")
            }
        }

        f.debug_tuple("TLConstructor")
            .field(&DummyForDebug)
            .finish()
    }
}

/// A mapping between TL constructor ids and corresponding TL constructor bodies.
#[derive(Debug)]
pub struct TLConstructorsMap(pub(crate) HashMap<u32, TLConstructor>);

impl TLConstructorsMap {
    pub fn new() -> TLConstructorsMap {
        TLConstructorsMap(HashMap::new())
    }

    pub fn add<T: TLObject + DeserializeOwned>(&mut self, type_id: u32) {
        self.0.insert(type_id, TLConstructor(Box::new(|deserializer| {
            erased_serde::deserialize::<T>(deserializer)
                .map(|obj| Box::new(obj) as Box<dyn TLObject>)
        })));
    }

    pub fn get(&self, type_id: u32) -> Option<&TLConstructor> {
        self.0.get(&type_id)
    }
}

impl<'de> DeserializeSeed<'de> for TLConstructorsMap {
    type Value = Box<dyn TLObject>;

    fn deserialize<D>(self, deserializer: D) -> Result<Box<dyn TLObject>, D::Error>
        where D: Deserializer<'de>
    {
        fn errconv<E: DeError>(kind: ErrorKind) -> E {
            E::custom(error::Error::from(kind))
        }

        struct BoxTLObjectVisitor(TLConstructorsMap);

        impl<'de> de::Visitor<'de> for BoxTLObjectVisitor {
            type Value = Box<dyn TLObject>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a boxed dynamically-typed value")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Box<dyn TLObject>, A::Error>
                where A: de::SeqAccess<'de>
            {
                struct BoxTLObjectSeed(TLConstructorsMap, u32);

                impl<'de> DeserializeSeed<'de> for BoxTLObjectSeed {
                    type Value = Box<dyn TLObject>;

                    fn deserialize<D>(self, deserializer: D) -> Result<Box<dyn TLObject>, D::Error>
                        where D: Deserializer<'de>
                    {
                        let ctor = &(self.0).0.get(&self.1)
                            .ok_or(errconv(ErrorKind::UnknownConstructorId("Box<TLObject>", self.1)))?.0;

                        ctor(&mut ErasedDeserializer::erase(deserializer)).map_err(|e| D::Error::custom(e))
                    }
                }

                let type_id = seq.next_element()?
                    .ok_or(errconv(ErrorKind::NotEnoughFields("Box<TLObject>", 0)))?;
                let object = seq.next_element_seed(BoxTLObjectSeed(self.0, type_id))?
                    .ok_or(errconv(ErrorKind::NotEnoughFields("Box<TLObject>", 1)))?;

                Ok(object)
            }
        }

        deserializer.deserialize_tuple(2, BoxTLObjectVisitor(self))
    }
}
