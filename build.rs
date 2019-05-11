use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use log::debug;
use quote::ToTokens;
use tl_lang_rust_interop::token_generator::TokenGenerator;


// Temporary fix for `std::error::Error::cause()` usage in `error_chain!`-generated code
// Should be resolved upstream in <https://github.com/rust-lang-nursery/error-chain/pull/255>
#[allow(deprecated)]
mod error {
    use error_chain::error_chain;

    error_chain! {
        foreign_links {
            Io(::std::io::Error);
            SetLogger(::log::SetLoggerError);
            TlLangSynParse(::tl_lang_syn::error::ParseError);
            Var(::std::env::VarError);
        }
    }
}


const TL_SCHEMA_DIR:       &'static str = "./tl";
const TL_SCHEMA_LIST_FILE: &'static str = "./tl/tl-schema-list.txt";
const RUST_SCHEMA_FILE:    &'static str = "./schema.rs";

fn collect_input() -> error::Result<String> {
    let mut tl_files = BufReader::new(File::open(TL_SCHEMA_LIST_FILE)?).lines().filter_map(|line| {
        match line {
            Ok(ref line) if line.trim_start().starts_with("//") => None,  // This line is a comment
            Ok(filename) => Some(Ok(Path::new(TL_SCHEMA_DIR).join(filename))),
            Err(e) => Some(Err(e)),  // Do not ignore errors
        }
    }).collect::<io::Result<Vec<PathBuf>>>()?;

    tl_files.sort();
    debug!("Files detected: {:?}", &tl_files);
    println!("cargo:rerun-if-changed={}", TL_SCHEMA_LIST_FILE);

    let mut input = String::new();
    for tl_file in tl_files {
        File::open(&tl_file)?.read_to_string(&mut input)?;
        println!("cargo:rerun-if-changed={}", tl_file.to_string_lossy());
    }

    Ok(input)
}


mod transformations {
    use std::iter;

    use quote::{ToTokens, TokenStreamExt, quote};
    use tl_lang_rust_interop::{
        token_generator::TokenGenerator,

        ConstructorDef, ConstructorDefNamespace,
        ConstructorVariant,
        Field, FieldNamed, FieldUnnamed,
        FunctionDef, FunctionDefNamespace,
        Ident,
        Path,
        Schema,
        Type, TypeBuiltIn,
        TypeDef, TypeDefNamespace,
    };


    fn ident_to_tokens(
        ident: &Ident,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let escaped_ident = match ident.0.as_str() {
            "type" => "type_",
            other => other,
        };

        tokens.append(proc_macro2::Ident::new(escaped_ident, proc_macro2::Span::call_site()));
    }

    fn path_to_tokens(
        path: &Path,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let tl_lang_syn::ParameterizedPath { ref path, ref args } = path.0;

        let segments = path.segments.iter().cloned().map(|ident| {
            proc_macro2::Ident::new(ident.as_str(), proc_macro2::Span::call_site())
        });

        let args = args.as_ref().map(|args| {
            match *args {
                tl_lang_syn::GenericArguments::AngleBracketed(ref args) => {
                    let args = args.args.iter().map(|path| {
                        let s = path.path.segments[0].as_str();
                        proc_macro2::Ident::new(s, proc_macro2::Span::call_site())
                    });
                    quote! { <#(#args),*> }
                },
                tl_lang_syn::GenericArguments::SpaceSeparated(ref args) => {
                    let args = args.args.iter().map(|path| {
                        let s = path.path.segments[0].as_str();
                        proc_macro2::Ident::new(s, proc_macro2::Span::call_site())
                    });
                    quote! { <#(#args),*> }
                },
            }
        });

        tokens.append_all(quote! {
            crate#(::#segments)* #args
        });
    }

    enum NeedsBox { No, Yes }

    fn field_to_tokens(
        field: &Field,
        needs_box: NeedsBox,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        tokens.append_all(match *field {
            Field::Named(FieldNamed { ref name, ref ty }) => {
                let name = TokenGenerator::new(name, ident_to_tokens);
                let ty = TokenGenerator::new(ty, type_to_tokens);

                match needs_box {
                    NeedsBox::No  => quote!(pub #name: #ty),
                    NeedsBox::Yes => quote!(pub #name: Box<#ty>),
                }
            },
            Field::Unnamed(FieldUnnamed { index, ref ty }) => {
                let ident = proc_macro2::Ident::new(
                    &format!("_field_{}", index),
                    proc_macro2::Span::call_site(),
                );
                let ty = TokenGenerator::new(ty, type_to_tokens);

                match needs_box {
                    NeedsBox::No  => quote!(pub #ident: #ty),
                    NeedsBox::Yes => quote!(pub #ident: Box<#ty>),
                }
            },
        });
    }

    fn field_to_tokens_box(field: &Field, tokens: &mut proc_macro2::TokenStream) {
        field_to_tokens(field, NeedsBox::Yes, tokens)
    }

    fn field_to_tokens_no_box(field: &Field, tokens: &mut proc_macro2::TokenStream) {
        field_to_tokens(field, NeedsBox::No, tokens)
    }

    fn field_consumed_to_tokens_no_box(field: Field, tokens: &mut proc_macro2::TokenStream) {
        field_to_tokens(&field, NeedsBox::No, tokens)
    }

    fn convert_field_type(field: &Field, from_type: &str, to_type: &str) -> Field {
        fn convert_path(
            parameterized_path: &tl_lang_syn::ParameterizedPath,
            from_type: &str,
            to_type: &str,
        ) -> tl_lang_syn::ParameterizedPath {
            let tl_lang_syn::ParameterizedPath { ref path, ref args } = *parameterized_path;

            match *args {
                None => {
                    if path.segments.len() >= 1 &&
                        path.segments.last().unwrap().into_value().as_str() == from_type
                    {
                        let ident = tl_lang_syn::Ident::new(
                            tl_lang_syn::span::Span::zeroed(),
                            to_type,
                        ).unwrap();

                        tl_lang_syn::ParameterizedPath {
                            path: tl_lang_syn::Path {
                                segments: path.segments
                                    .iter()
                                    .take(path.segments.len() - 1)
                                    .cloned()
                                    .chain(iter::once(ident))
                                    .collect(),
                            },
                            args: None,
                        }
                    } else {
                        parameterized_path.clone()
                    }
                },
                Some(ref args) => {
                    // Recurse on arguments
                    let args = match *args {
                        tl_lang_syn::GenericArguments::AngleBracketed(ref angle_bracketed) => {
                            tl_lang_syn::GenericArguments::AngleBracketed(
                                tl_lang_syn::AngleBracketedGenericArguments {
                                    langle_token: angle_bracketed.langle_token.clone(),
                                    args: angle_bracketed.args
                                        .iter()
                                        .map(|arg| convert_path(arg, from_type, to_type))
                                        .collect(),
                                    rangle_token: angle_bracketed.rangle_token.clone(),
                                }
                            )
                        },
                        tl_lang_syn::GenericArguments::SpaceSeparated(ref space_separated) => {
                            tl_lang_syn::GenericArguments::SpaceSeparated(
                                tl_lang_syn::SpaceSeparatedGenericArguments {
                                    args: space_separated.args
                                        .iter()
                                        .map(|arg| convert_path(arg, from_type, to_type))
                                        .collect(),
                                }
                            )
                        },
                    };

                    tl_lang_syn::ParameterizedPath {
                        path: path.clone(),
                        args: Some(args),
                    }
                },
            }
        }

        fn convert_type(ty: &Type, from_type: &str, to_type: &str) -> Type {
            match *ty {
                Type::Path(Path(ref parameterized_path)) => {
                    Type::Path(Path(convert_path(parameterized_path, from_type, to_type)))
                },
                Type::BuiltIn(TypeBuiltIn::Vector(ref type_params)) => {
                    Type::BuiltIn(TypeBuiltIn::Vector(type_params
                        .iter()
                        .map(|type_param| convert_type(type_param, from_type, to_type))
                        .collect())
                    )
                },
                Type::BuiltIn(TypeBuiltIn::VectorBoxed(ref type_params)) => {
                    Type::BuiltIn(TypeBuiltIn::VectorBoxed(type_params
                        .iter()
                        .map(|type_param| convert_type(type_param, from_type, to_type))
                        .collect()))
                },
                ref other => other.clone(),
            }
        }

        match *field {
            Field::Named(FieldNamed { ref name, ref ty }) => Field::Named(FieldNamed {
                name: name.clone(),
                ty: convert_type(ty, from_type, to_type),
            }),
            Field::Unnamed(FieldUnnamed { index, ref ty }) => Field::Unnamed(FieldUnnamed {
                index,
                ty: convert_type(ty, from_type, to_type),
            }),
        }
    }

    fn string_field_to_bytes_field(string_field: &Field) -> Field {
        match *string_field {
            Field::Named(FieldNamed { ref name, ty: Type::BuiltIn(TypeBuiltIn::String) }) => {
                Field::Named(FieldNamed { name: name.clone(), ty: Type::BuiltIn(TypeBuiltIn::Bytes) })
            },
            ref other => other.clone(),
        }
    }

    fn choose_field_to_tokens_function(
        field: &Field,
        type_to_box: &str,
    ) -> fn(&Field, &mut proc_macro2::TokenStream) {
        if let Field::Named(FieldNamed {
            ty: Type::Path(Path(tl_lang_syn::ParameterizedPath {
                path: tl_lang_syn::Path { ref segments },
                args: None,
            })),
            ..
        }) = *field {
            if segments.len() >= 1 && segments.last().unwrap().into_value().as_str() == type_to_box {
                return field_to_tokens_box;
            }
        }

        field_to_tokens_no_box
    }

    fn type_built_in_to_tokens(
        type_built_in: &TypeBuiltIn,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        tokens.append_all(match *type_built_in {
            TypeBuiltIn::Bool   => quote!(bool),
            TypeBuiltIn::True   => quote!(()),
            TypeBuiltIn::Int    => quote!(i32),
            TypeBuiltIn::Long   => quote!(i64),
            TypeBuiltIn::Int128 => quote!(i128),
            TypeBuiltIn::Int256 => quote!(crate::manual_types::i256::I256),
            TypeBuiltIn::Double => quote!(f64),
            TypeBuiltIn::Bytes  => quote!(::serde_bytes::ByteBuf),
            TypeBuiltIn::String => quote!(String),
            TypeBuiltIn::Vector(ref args) => {
                let args = args.iter().map(|arg| TokenGenerator::new(arg, type_to_tokens));
                quote!(Vec<#(#args),*>)
            },
            TypeBuiltIn::VectorBoxed(ref args) => {
                let args = args.iter().map(|arg| TokenGenerator::new(arg, type_to_tokens));
                quote!(::serde_mtproto::Boxed<Vec<#(#args),*>>)
            },
        });
    }

    fn type_to_tokens(
        ty: &Type,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        match *ty {
            Type::BuiltIn(ref built_in) => {
                let built_in = TokenGenerator::new(built_in, type_built_in_to_tokens);
                built_in.to_tokens(tokens)
            },
            Type::Path(ref path) => {
                let path = TokenGenerator::new(path, path_to_tokens);
                path.to_tokens(tokens)
            },
            Type::Generic(ref type_param) => {
                let type_param = TokenGenerator::new(type_param, ident_to_tokens);
                type_param.to_tokens(tokens)
            },
        }
    }

    fn type_def_namespace_to_tokens(
        type_def_ns: &TypeDefNamespace,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let TypeDefNamespace { ref name, ref type_defs, ref namespaces } = *type_def_ns;

        let name = TokenGenerator::new(name, ident_to_tokens);
        let type_defs = type_defs.values()
            .map(|tdef| TokenGenerator::new(tdef, type_def_to_tokens));
        let namespaces = namespaces.values()
            .map(|ns| TokenGenerator::new(ns, type_def_namespace_to_tokens));

        tokens.append_all(quote! {
            pub mod #name {
                #(#type_defs)*
                #(#namespaces)*
            }
        });
    }

    fn type_def_to_tokens(
        type_def: &TypeDef,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let TypeDef { ref name, ref constructor_variants } = *type_def;

        let name = TokenGenerator::new(name, ident_to_tokens);
        let constructor_variants = constructor_variants.iter()
            .map(|cvar| TokenGenerator::new(cvar, constructor_variant_to_tokens));

        tokens.append_all(quote! {
            #[derive(
                Clone, Debug, PartialEq,
                serde_derive::Serialize, serde_derive::Deserialize,
                serde_mtproto_derive::MtProtoIdentifiable, serde_mtproto_derive::MtProtoSized,
            )]
            pub enum #name {
                #(#constructor_variants,)*
            }

            impl crate::tl::TLObject for #name {
                fn object_type() -> crate::tl::dynamic::ObjectType {
                    crate::tl::dynamic::ObjectType::Type
                }
            }
        });
    }

    fn constructor_variant_to_tokens(
        constructor_variant: &ConstructorVariant,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let ConstructorVariant { ref name, id, ref struct_path } = *constructor_variant;

        let quoted_name = match name.as_str() {
            // There are both `updates` module and `updates` constructor.
            // Let's escape the constructor variant name because the module one
            // is expected to be used often.
            //
            // TODO: generalize?
            "updates" => quote!(updates_),
            _ => TokenGenerator::new(name, ident_to_tokens).into_token_stream(),
        };
        let id_hex_string = format!("{:#x}", id);
        // There are both `updates` module and `updates` constructor.
        // Let's escape the constructor name because the module one is expected
        // to be used often.
        //
        // TODO: generalize?
        let segments = &struct_path.0.path.segments;
        let struct_path = match segments.last().map(tl_lang_syn::punctuated::Pair::into_value) {
            Some(last_segment) if last_segment.as_str() == "updates" => {
                let segments_before_last = segments
                    .iter()
                    .take(segments.len() - 1)
                    .map(|segment| proc_macro2::Ident::new(
                        segment.as_str(),
                        proc_macro2::Span::call_site(),
                    ));

                quote!(crate#(::#segments_before_last)*::updates_)
            },
            _ => TokenGenerator::new(struct_path, path_to_tokens).into_token_stream(),
        };

        tokens.append_all(quote! {
            #[mtproto_identifiable(id = #id_hex_string)]
            #quoted_name(#struct_path)
        });
    }

    fn constructor_def_namespace_to_tokens(
        constructor_def_ns: &ConstructorDefNamespace,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let ConstructorDefNamespace {
            ref name,
            ref constructor_defs,
            ref namespaces,
        } = *constructor_def_ns;

        let name = TokenGenerator::new(name, ident_to_tokens);
        let constructor_defs = constructor_defs.iter()
            .map(|cdef| TokenGenerator::new(cdef, constructor_def_to_tokens));
        let namespaces = namespaces.values()
            .map(|ns| TokenGenerator::new(ns, constructor_def_namespace_to_tokens));

        tokens.append_all(quote! {
            pub mod #name {
                #(#constructor_defs)*
                #(#namespaces)*
            }
        });
    }

    fn constructor_def_to_tokens(
        constructor_def: &ConstructorDef,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let ConstructorDef { ref name, ref fields } = *constructor_def;

        let quoted_name = match name.as_str() {
            // There are both `updates` module and `updates` constructor.
            // Let's escape the constructor name because the module one is
            // expected to be used often.
            //
            // TODO: generalize?
            "updates" => quote!(updates_),
            _ => TokenGenerator::new(name, ident_to_tokens).into_token_stream(),
        };

        let fields = if fields.is_empty() {
            quote!(;)
        } else {
            // Special-case several constructors so that we could work with them
            // properly.
            //
            // Why not just modify them in the source TL? Because their ids (aka
            // CRC32 of combinator strings) will change as well and that will
            // make communication with Telegram servers impossible.
            match name.as_str() {
                "resPQ"                |
                "p_q_inner_data"       |
                "p_q_inner_data_temp"  |
                "server_DH_params_ok"  |
                "server_DH_inner_data" |
                "client_DH_inner_data" => {
                    let modified_fields = fields.iter().map(|field| {
                        let modified_field = string_field_to_bytes_field(field);
                        TokenGenerator::new(modified_field, field_consumed_to_tokens_no_box)
                    });

                    quote! {
                        { #(#modified_fields,)* }
                    }
                },
                "future_salts" => {
                    let modified_fields = fields.iter().map(|field| {
                        let modified_field = convert_field_type(field, "future_salt", "FutureSalt");
                        TokenGenerator::new(modified_field, field_consumed_to_tokens_no_box)
                    });

                    quote! {
                        { #(#modified_fields,)* }
                    }
                },
                "configSimple" => {
                    let modified_fields = fields.iter().map(|field| {
                        let modified_field = convert_field_type(field, "ipPort", "IpPort");
                        TokenGenerator::new(modified_field, field_consumed_to_tokens_no_box)
                    });

                    quote! {
                        { #(#modified_fields,)* }
                    }
                },
                "textBold"      |
                "textItalic"    |
                "textUnderline" |
                "textStrike"    |
                "textFixed"     |
                "textUrl"       |
                "textEmail"     => {
                    let modified_fields = fields.iter().map(|field| {
                        let function = choose_field_to_tokens_function(field, "RichText");
                        TokenGenerator::new(field, function)
                    });

                    quote! {
                        { #(#modified_fields,)* }
                    }
                },
                "pageBlockCover" => {
                    let modified_fields = fields.iter().map(|field| {
                        let function = choose_field_to_tokens_function(field, "PageBlock");
                        TokenGenerator::new(field, function)
                    });

                    quote! {
                        { #(#modified_fields,)* }
                    }
                },
                _ => {
                    let fields = fields.iter().map(|field| {
                        TokenGenerator::new(field, field_to_tokens_no_box)
                    });

                    quote! {
                        { #(#fields,)* }
                    }
                },
            }
        };

        tokens.append_all(quote! {
            #[derive(
                Clone, Debug, PartialEq,
                serde_derive::Serialize, serde_derive::Deserialize,
                serde_mtproto_derive::MtProtoSized,
            )]
            pub struct #quoted_name #fields
        });
    }

    fn function_def_namespace_to_tokens(
        function_def_ns: &FunctionDefNamespace,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let FunctionDefNamespace {
            ref name,
            ref function_defs,
            ref namespaces,
        } = *function_def_ns;

        let name = TokenGenerator::new(name, ident_to_tokens);
        let function_defs = function_defs.iter()
            .map(|fdef| TokenGenerator::new(fdef, function_def_to_tokens));
        let namespaces = namespaces.values()
            .map(|ns| TokenGenerator::new(ns, function_def_namespace_to_tokens));

        tokens.append_all(quote! {
            pub mod #name {
                #(#function_defs)*
                #(#namespaces)*
            }
        });
    }

    fn function_def_to_tokens(
        function_def: &FunctionDef,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let FunctionDef { ref name, id, ref generics, ref fields, .. } = *function_def;

        let name = TokenGenerator::new(name, ident_to_tokens);
        let id_hex_string = format!("{:#x}", id);
        let (generics, impl_generics) = if generics.is_empty() {
            (None, None)
        } else {
            let generics = generics.iter().map(|gen| TokenGenerator::new(gen, ident_to_tokens));
            let generics2 = generics.clone();

            (
                Some(quote!(<#(#generics),*>)),
                Some(quote!(<#(#generics2:
                    ::std::clone::Clone +
                    ::serde::Serialize +
                    ::serde_mtproto::MtProtoSized +
                    'static
                ),*>)),
            )
        };
        let fields = if fields.is_empty() {
            quote!(;)
        } else {
            match name.value().as_str() {
                "req_DH_params"        |
                "set_client_DH_params" => {
                    let modified_fields = fields.iter().map(|field| {
                        let modified_field = string_field_to_bytes_field(field);
                        TokenGenerator::new(modified_field, field_consumed_to_tokens_no_box)
                    });

                    quote! {
                        { #(#modified_fields,)* }
                    }
                },
                _ => {
                    let fields = fields.iter().map(|field| {
                        TokenGenerator::new(field, field_to_tokens_no_box)
                    });

                    quote! {
                        { #(#fields,)* }
                    }
                },
            }
        };

        tokens.append_all(quote! {
            #[derive(
                Clone, Debug, PartialEq,
                serde_derive::Serialize, serde_derive::Deserialize,
                serde_mtproto_derive::MtProtoIdentifiable, serde_mtproto_derive::MtProtoSized,
            )]
            #[mtproto_identifiable(id = #id_hex_string)]
            pub struct #name #generics #fields

            impl #impl_generics crate::tl::TLObject for #name #generics {
                fn object_type() -> crate::tl::dynamic::ObjectType {
                    crate::tl::dynamic::ObjectType::Function
                }
            }
        });
    }

    pub(super) fn schema_to_tokens(
        schema: &Schema,
        tokens: &mut proc_macro2::TokenStream,
    ) {
        let Schema {
            layer,
            ref type_def_ns,
            ref constructor_def_ns,
            ref function_def_ns,
        } = *schema;

        let type_def_ns =
            TokenGenerator::new(type_def_ns, type_def_namespace_to_tokens);
        let constructor_def_ns =
            TokenGenerator::new(constructor_def_ns, constructor_def_namespace_to_tokens);
        let function_def_ns =
            TokenGenerator::new(function_def_ns, function_def_namespace_to_tokens);

        let doc = proc_macro2::Literal::string(&format!(
            "/// Autogenerated TL-schema for Telegram API. Currently layer {}.",
            layer,
        ));

        tokens.append_all(quote! {
            #[doc = #doc]
            #[allow(non_camel_case_types)]
            pub mod schema {
                pub const LAYER: u32 = #layer;

                #type_def_ns
                #constructor_def_ns
                #function_def_ns
            }
        });
    }
}


fn main() -> error::Result<()> {
    env_logger::try_init()?;

    let input = collect_input()?;
    let parse_tree = tl_lang_syn::parse_file_str(&input)?;
    let schema = tl_lang_rust_interop::Schema::from_tl_file(&parse_tree);
    let code = TokenGenerator::new(&schema, transformations::schema_to_tokens)
        .into_token_stream()
        .to_string();
    debug!("Code size: {} bytes", code.len());

    let rust_schema_file = Path::new(&env::var("OUT_DIR")?).join(RUST_SCHEMA_FILE);
    File::create(&rust_schema_file)?.write_all(code.as_str().as_bytes())?;
    debug!("Successful write to {:?}", rust_schema_file);

    Command::new("rustfmt")
        .arg(&rust_schema_file)
        .status()?;

    Ok(())
}
