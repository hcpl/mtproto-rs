use std::collections::{BTreeMap, BTreeSet};

use quote;
use syn;

use analyzer::{ConstructorInputData, PathGlobalSegmentsTyParams, TypeckKind,
               build_transform_dag, analyze_dag};
use ast::{Constructor, Delimiter, Item, Type, TypeFixupMap, TypeIrKind,
          no_conflict_ident, wrap_option_type, wrap_option_value};
use error;
use parser;


pub fn generate_code_for(input: &str) -> quote::Tokens {
    let krate = generate_ast_for(input);

    quote! { #krate }
}

pub fn generate_ast_for(input: &str) -> syn::Crate {
    let mut constructors = {
        let mut items = parser::parse_string(input).unwrap();
        filter_items(&mut items);
        partition_by_delimiter_and_namespace(items)
    };

    let layer = constructors.layer as i32;
    let module_level_docs = syn::Attribute {
        style: syn::AttrStyle::Inner,
        value: syn::MetaItem::NameValue(
            "doc".into(),
            syn::Lit::Str(
                format!("//! Autogenerated TL-schema for Telegram API. Currently layer {}.", layer),
                syn::StrStyle::Cooked,
            ),
        ),
        is_sugared_doc: true,
    };
    let mut krate = syn::parse_crate(quote! {
        #module_level_docs
        #![allow(non_camel_case_types)]

        pub const LAYER: i32 = #layer;
    }.as_str()).unwrap();

    let variants_to_outputs: TypeFixupMap = constructors.types.iter()
        .flat_map(|(namespaces, constructor_map)| {
            constructor_map.iter().flat_map(move |(output, constructors)| {
                constructors.0.iter().filter_map(move |constructor| {
                    let variant_name = match constructor.variant {
                        Type::Named(ref n) => n,
                        _ => return None,
                    };

                    let mut full_output: Vec<String> = namespaces.iter().cloned().collect();
                    full_output.push(output.clone());

                    Some((variant_name.clone(), full_output))
                })
            })
        })
        .collect();

    fn process_namespaces<I>(items_buf: &mut Vec<syn::Item>, namespaces: &[String], items: I)
        where I: IntoIterator<Item=syn::Item>
    {
        if namespaces.is_empty() {
            items_buf.extend(items);
        } else {
            let mut namespaces_rev_iter = namespaces.iter().cloned().rev();

            let namespace = syn::Ident::new(namespaces_rev_iter.next().unwrap()); // safe to unwrap
            let mut syn_mod = syn::parse_item(quote! {
                pub mod #namespace {
                    #(#items)*
                }
            }.as_str()).unwrap();

            for namespace in namespaces_rev_iter {
                let namespace = syn::Ident::new(namespace);
                syn_mod = syn::parse_item(quote! {
                    pub mod #namespace {
                        #syn_mod
                    }
                }.as_str()).unwrap();
            }

            items_buf.push(syn_mod);
        }
    };

    for (_namespaces, constructor_map) in &mut constructors.types {
        for ctor in constructor_map.values_mut() {
            ctor.fixup(Delimiter::Types, &variants_to_outputs);
        }
    }

    for (_namespaces, substructs) in &mut constructors.functions {
        substructs.sort_by(|c1, c2| c1.variant.cmp(&c2.variant));
        for ctor in substructs {
            ctor.fixup(Delimiter::Functions, &variants_to_outputs);
        }
    }

    let ctors_typeck_info = constructors.ctors_typeck_info();

    let mut dynamic_ctors: Vec<(Vec<String>, u32, syn::Stmt)> = vec![];
    for (namespaces, constructor_map) in &constructors.types {
        dynamic_ctors.extend(constructor_map.values()
            .flat_map(|c| c.to_syn_dynamic_ctors(&ctors_typeck_info).unwrap())); // FIXME

        let substructs = constructor_map.values()
            .flat_map(|c| c.to_syn_data_type_items(&ctors_typeck_info).unwrap()); // FIXME

        process_namespaces(&mut krate.items, namespaces, substructs);
    }

    dynamic_ctors.sort_by(|&(ref names1, tl_id1, ref _stmt1), &(ref names2, tl_id2, ref _stmt2)| {
        names1.cmp(names2).then(tl_id1.cmp(&tl_id2))
    });

    let stmts: Vec<syn::Stmt> = dynamic_ctors.into_iter().map(|(_, _, stmt)| stmt).collect();
    let register_ctors = syn::parse_item(quote! {
        /// Registers all generated deserializable constructors to the provided constructors map
        pub fn register_ctors(cstore: &mut ::tl::dynamic::TLConstructorsMap) {
            #(#stmts)*
        }
    }.as_str()).unwrap();
    krate.items.push(register_ctors);

    let mut rpc_items = vec![];
    for (namespaces, substructs) in &constructors.functions {
        let substructs = substructs.into_iter()
            .flat_map(|c| {
                c.to_syn_function_struct(&ctors_typeck_info).unwrap() // FIXME
            });

        process_namespaces(&mut rpc_items, namespaces, substructs);
    }

    krate.items.push(syn::parse_item(quote! {
        pub mod rpc {
            #(#rpc_items)*
        }
    }.as_str()).unwrap());

    krate
}

fn filter_items(items: &mut Vec<Item>) {
    items.retain(|item| {
        let c = match *item {
            Item::Constructor(ref c) => c,
            _ => return true,
        };

        // Blacklist some annoying inconsistencies.
        match c.variant.name() {
            Some("true") |
            Some("vector") => false,
            _ => true,
        }
    });
}

fn partition_by_delimiter_and_namespace(items: Vec<Item>) -> AllConstructors {
    let mut current = Delimiter::Types;
    let mut result = AllConstructors {
        types: BTreeMap::new(),
        functions: BTreeMap::new(),
        layer: 0,
    };

    for item in items {
        match item {
            Item::Delimiter(d) => current = d,
            Item::Constructor(c) => {
                match current {
                    Delimiter::Types => {
                        result.types.entry(c.output.namespace().unwrap().to_vec()) // FIXME
                            .or_insert_with(Default::default)
                            .entry(c.output.name().map(Into::into).unwrap()) // FIXME
                            .or_insert_with(Default::default)
                            .0.push(c);
                    },
                    Delimiter::Functions => {
                        result.functions.entry(c.variant.namespace().unwrap().to_vec()) // FIXME
                            .or_insert_with(Default::default)
                            .push(c);
                    },
                }
            },
            Item::Layer(i) => result.layer = i,
        }
    }

    result
}


#[derive(Debug, Default)]
struct Constructors(Vec<Constructor>);

impl Constructors {
    fn fixup(&mut self, delim: Delimiter, fixup_map: &TypeFixupMap) {
        for c in &mut self.0 {
            c.fixup(delim, fixup_map);
        }
    }

    fn to_syn_data_type_items<'a>(&self, ctors_typeck_info: &BTreeMap<&'a Constructor, TypeckKind>) -> error::Result<Vec<syn::Item>> {
        if self.0.len() == 1 {
            return self.0[0].to_syn_single_type_struct(ctors_typeck_info).map(|s| vec![s]);
        }

        assert!(self.0.len() >= 2); // FIXME: return errors instead of assert

        let name = self.0[0].output.name().map(no_conflict_ident).unwrap(); // FIXME
        let variants: Vec<syn::Variant> = self.0.iter().map(Constructor::to_syn_variant).collect();
        let methods = self.determine_methods(&name)?;
        let structs = self.0.iter()
            .map(|ctor| ctor.to_syn_variant_type_struct(&ctors_typeck_info))
            .collect::<error::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|maybe_struct| maybe_struct);

        let is_static_typeck_kind = self.0.iter()
            .map(|ctor| ctors_typeck_info[ctor])
            .all(|kind| kind == TypeckKind::Static);
        let typeck_kind = if is_static_typeck_kind { TypeckKind::Static } else { TypeckKind::Dynamic };

        let mut derives = typeck_kind.infer_basic_derives();
        derives.push("MtProtoIdentifiable");

        let derives = derives.into_iter().map(syn::Ident::new);
        let syn_enum = syn::parse_item(quote! {
            #[derive( #(#derives),* )]
            pub enum #name {
                #(#variants,)*
            }
        }.as_str()).unwrap();

        let syn_data_type_items = {
            // enum & impl & structs; structs.len() == self.0.len()
            let mut v = Vec::with_capacity(1 + 1 + self.0.len());

            v.push(syn_enum);
            v.extend(methods);
            v.extend(structs);

            v
        };

        Ok(syn_data_type_items)
    }

    fn determine_methods(&self, enum_name: &syn::Ident) -> error::Result<Option<syn::Item>> {
        let all_constructors_count = self.0.len();
        let mut methods = vec![];

        for (method_name, typemap) in self.coalesce_methods() {
            if typemap.len() != 1 {
                continue;
            }

            // FIXME: handle case when typemap.len() == 0
            let (output_type, constructors) = typemap.into_iter().next().unwrap();
            if constructors.len() <= 1 {
                //panic!("{:#?}", constructors);
                continue;
            }

            let method_name_no_conflict = no_conflict_ident(method_name);
            let mut type_ir = output_type.to_type_ir()?;

            let field_is_option = type_ir.needs_option();
            let exhaustive = constructors.len() == all_constructors_count;
            if !exhaustive {
                type_ir.with_option = true;
            }

            let force_option = !exhaustive && type_ir.kind == TypeIrKind::Unit;
            let field_access = syn::ExprKind::Field(
                Box::new(syn::ExprKind::Path(None, "x".into()).into()),
                method_name_no_conflict.clone(),
            ).into();

            let value = if field_is_option && type_ir.kind != TypeIrKind::Copyable {
                syn::ExprKind::MethodCall(syn::Ident::new("as_ref"), vec![], vec![field_access]).into()
            } else {
                let field_access = if type_ir.kind == TypeIrKind::Copyable {
                    field_access
                } else {
                    syn::ExprKind::AddrOf(syn::Mutability::Immutable, Box::new(field_access)).into()
                };

                let wrap = (type_ir.needs_option() && !field_is_option) || force_option;
                wrap_option_value(wrap, field_access)
            };

            let ty = wrap_option_type(force_option, type_ir.ref_type());
            let mut constructors_match_arms: Vec<syn::Arm> = constructors.into_iter()
                .map(|c| {
                    syn::Arm {
                        attrs: vec![],
                        pats: vec![
                            syn::Pat::TupleStruct(
                                syn::Path {
                                    global: false,
                                    segments: vec![
                                        enum_name.clone().into(),
                                        c.variant_name().into(),
                                    ],
                                },
                                vec![
                                    syn::Pat::Ident(
                                        syn::BindingMode::ByRef(syn::Mutability::Immutable),
                                        syn::Ident::new("x"),
                                        None,
                                    ),
                                ],
                                None,
                            ),
                        ],
                        guard: None,
                        body: Box::new(value.clone()),
                    }
                })
                .collect();

            if !exhaustive {
                let arm_ignore = syn::Arm {
                    attrs: vec![],
                    pats: vec![syn::Pat::Wild],
                    guard: None,
                    body: Box::new(syn::Expr {
                        node: syn::ExprKind::Path(None, "None".into()),
                        attrs: vec![],
                    }),
                };

                constructors_match_arms.push(arm_ignore);
            }

            let method = syn::ImplItem {
                ident: method_name_no_conflict,
                vis: syn::Visibility::Public,
                defaultness: syn::Defaultness::Final,
                attrs: vec![],
                node: syn::ImplItemKind::Method(
                    syn::MethodSig {
                        unsafety: syn::Unsafety::Normal,
                        constness: syn::Constness::NotConst,
                        abi: None,
                        decl: syn::FnDecl {
                            inputs: vec![
                                syn::FnArg::SelfRef(None, syn::Mutability::Immutable),
                            ],
                            output: syn::FunctionRetTy::Ty(ty),
                            variadic: false,
                        },
                        generics: Default::default(),
                    },
                    syn::Block {
                        stmts: vec![
                            syn::Stmt::Expr(Box::new(syn::ExprKind::Match(
                                Box::new(syn::ExprKind::Unary(
                                    syn::UnOp::Deref,
                                    Box::new(syn::ExprKind::Path(
                                        None,
                                        "self".into(),
                                    ).into()),
                                ).into()),
                                constructors_match_arms,
                            ).into())),
                        ],
                    },
                ),
            };

            methods.push(method);
        }

        let maybe_item = if methods.is_empty() {
            None
        } else {
            let item = syn::parse_item(quote! {
                impl #enum_name {
                    #(#methods)*
                }
            }.as_str()).unwrap();

            Some(item)
        };

        Ok(maybe_item)
    }

    fn coalesce_methods(&self) -> BTreeMap<&str, BTreeMap<&Type, BTreeSet<&Constructor>>> {
        let mut map: BTreeMap<_, BTreeMap<_, BTreeSet<_>>> = BTreeMap::new();

        for constructor in &self.0 {
            for field in constructor.non_flag_fields() {
                let name = match field.name.as_ref() {
                    Some(s) => s.as_str(),
                    None => continue,
                };

                map.entry(name)
                    .or_insert_with(Default::default)
                    .entry(&field.ty)
                    .or_insert_with(Default::default)
                    .insert(constructor);
            }
        }

        map
    }

    fn to_syn_dynamic_ctors<'a>(&self, ctors_typeck_info: &BTreeMap<&'a Constructor, TypeckKind>)
        -> error::Result<Vec<(Vec<String>, u32, syn::Stmt)>>
    {
        let syn_output_ty = self.0[0].output.to_type_ir()?.unboxed();
        let ty_name = self.0[0].output.names_vec().unwrap();  // FIXME

        let dynamic_ctors = self.0.iter().filter_map(|c| {
            if ctors_typeck_info[c] == TypeckKind::Dynamic {
                return None;
            }

            c.tl_id.map(|tl_id| {
                let syn_add = syn::Stmt::Semi(
                    Box::new(syn::parse_expr(quote! {
                        cstore.add::<#syn_output_ty>(#tl_id)
                    }.as_str()).unwrap())
                );

                (ty_name.clone(), tl_id, syn_add)
            })
        }).collect();

        Ok(dynamic_ctors)
    }
}


#[derive(Debug)]
struct AllConstructors {
    types: BTreeMap<Vec<String>, BTreeMap<String, Constructors>>,
    functions: BTreeMap<Vec<String>, Vec<Constructor>>,
    layer: u32,
}

impl AllConstructors {
    fn ctors_typeck_info<'a>(&'a self) -> BTreeMap<&'a Constructor, TypeckKind> {
        let all_ctors_input_data = self.prepare_input_data_for_dag();
        let dag = build_transform_dag(all_ctors_input_data);
        let ctors_typeck_kinds = analyze_dag(dag);

        ctors_typeck_kinds
    }

    fn prepare_input_data_for_dag<'a>(&'a self) -> Vec<ConstructorInputData<'a>> {
        fn get_unrolled_syn_ty(namespaces: &[String], ty: &Type) -> PathGlobalSegmentsTyParams {
            fn split_path_to_global_segments(namespaces: &[String], path: syn::Path)
                -> PathGlobalSegmentsTyParams
            {
                let mut split = vec![vec![]];

                if !path.global {
                    split[0].extend(namespaces.iter().cloned().map(Into::into));
                }

                for seg in path.segments {
                    split[0].push(seg.ident);

                    match seg.parameters {
                        syn::PathParameters::AngleBracketed(data) => {
                            assert!(data.lifetimes.is_empty());
                            assert!(data.bindings.is_empty());

                            split.extend(data.types.into_iter().flat_map(|ty| {
                                match ty {
                                    syn::Ty::Path(None, path) => split_path_to_global_segments(namespaces, path),
                                    _ => unreachable!(),
                                }
                            }));
                        },
                        syn::PathParameters::Parenthesized(_) => unreachable!(),
                    }
                }

                split
            };

            match ty.to_type_ir().unwrap().unboxed() {  // FIXME
                syn::Ty::Path(None, path) => split_path_to_global_segments(namespaces, path),
                syn::Ty::Tup(tys) => {
                    tys.into_iter().flat_map(|syn_ty| {
                        match syn_ty {
                            syn::Ty::Path(None, path) => split_path_to_global_segments(namespaces, path),
                            ty => unreachable!("`syn::Ty` encountered: {:#?}", ty),
                        }
                    }).collect()
                },
                ty => unreachable!("`syn::Ty` encountered: {:#?}", ty),
            }
        }

        fn get_input_data<'a>(namespaces: &[String], ctor: &'a Constructor)
            -> ConstructorInputData<'a>
        {
            let unrolled_output_syn_ty = get_unrolled_syn_ty(namespaces, &ctor.output);
            let kind = match ctor.output.to_type_ir().unwrap().kind { // FIXME
                TypeIrKind::Dynamic => TypeckKind::Dynamic,
                _ => {
                    let is_dynamic = ctor.fields.iter()
                        .any(|f| f.ty.to_type_ir().unwrap().kind == TypeIrKind::Dynamic); // FIXME

                    if is_dynamic { TypeckKind::Dynamic } else { TypeckKind::Static }
                },
            };
            let deps = ctor.fields.iter().map(|f| get_unrolled_syn_ty(namespaces, &f.ty)).collect();

            ConstructorInputData {
                ty: unrolled_output_syn_ty,
                kind: kind,
                deps: deps,
                ctor: ctor,
            }
        }

        let mut all_ctors_input_data = vec![];

        for (namespaces, ty_data) in &self.types {
            for (_ty_name, ty_ctors) in ty_data {
                for ty_ctor in &ty_ctors.0 {
                    let input_data = get_input_data(&namespaces, ty_ctor);
                    all_ctors_input_data.push(input_data);
                }
            }
        }

        for (namespaces, fn_ctors) in &self.functions {
            for fn_ctor in fn_ctors {
                let input_data = get_input_data(&namespaces, fn_ctor);
                all_ctors_input_data.push(input_data);
            }
        }

        all_ctors_input_data
    }
}
