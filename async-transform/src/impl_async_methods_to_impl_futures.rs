use quote::quote;
use syn::parse_quote;


pub(crate) fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    if !attr.is_empty() {
        macro_no_args_error!(attr, module_path!());
    }

    if let Ok(mut item_impl) = syn::parse2::<syn::ItemImpl>(item.clone()) {
        if item_impl.trait_.is_some() {
            macro_error!(item_impl, module_path!(), "can only be used on inherent `impl` items");
        }

        let mut captures = proc_macro2::TokenStream::new();

        let impl_lifetimes = item_impl.generics.lifetimes()
            .map(|lifetime_def| &lifetime_def.lifetime)
            .collect::<Vec<_>>();

        for impl_item in &mut item_impl.items {
            match *impl_item {
                syn::ImplItem::Method(ref mut impl_item_method) => {
                    if impl_item_method.sig.asyncness.is_some() {
                        let captures_ident = proc_macro2::Ident::new(
                            &format!("__Captures_impl_{}_method_{}", mangle_type(&item_impl.self_ty), impl_item_method.sig.ident),
                            proc_macro2::Span::call_site(),
                        );

                        transform_impl_item_method(impl_item_method, &impl_lifetimes, &captures_ident);

                        let vis = &impl_item_method.vis;

                        captures.extend(quote! {
                            #vis trait #captures_ident<'a> {}
                            impl<'a, T> #captures_ident<'a> for T {}
                        });
                    }
                },
                _ => (),
            }
        }

        quote! {
            #captures

            #item_impl
        }
    } else {
        macro_error!(item, module_path!(), "can only be used on inherent `impl` items");
    }
}


fn transform_impl_item_method(
    impl_item_method: &mut syn::ImplItemMethod,
    impl_lifetimes: &[&syn::Lifetime],
    captures_ident: &proc_macro2::Ident,
) {
    impl_item_method.sig.asyncness = None;

    crate::transform::fn_decl_for_impl_future(&mut impl_item_method.sig.decl, impl_lifetimes, captures_ident);

    let orig_block = &impl_item_method.block;
    impl_item_method.block = parse_quote!({ async move #orig_block });
}

/*fn transform_fn_decl(
    fn_decl: &mut syn::FnDecl,
    impl_lifetimes: &[&syn::Lifetime],
    captures_ident: &proc_macro2::Ident,
) {
    let syn::FnDecl {
        ref mut generics,
        ref mut inputs,
        ref mut output,
        ..
    } = *fn_decl;

    let res_lifetime = syn::Lifetime::new("'__res", proc_macro2::Span::call_site());
    generics.params.push(parse_quote!(#res_lifetime));

    let mut impl_future: syn::TypeImplTrait = match output {
        syn::ReturnType::Default => {
            parse_quote!(impl ::core::future::Future<Output = ()>)
        },
        syn::ReturnType::Type(_r_arrow, ty) => {
            parse_quote!(impl ::core::future::Future<Output = #ty>)
        },
    };

    let mut fn_arg_transform = crate::FnArgTransform::new_for_impl_future(
        generics,
        &res_lifetime,
        &mut impl_future,
        captures_ident,
    );

    for impl_lifetime in impl_lifetimes {
        fn_arg_transform.bind_lifetime(impl_lifetime);
    }

    for input in inputs {
        syn::visit_mut::visit_fn_arg_mut(&mut fn_arg_transform, input);
    }

    impl_future.bounds.push(parse_quote!(#res_lifetime));
    *output = parse_quote!(-> #impl_future);
}*/


fn mangle_type(ty: &syn::Type) -> String {
    let mut buf = String::new();
    impl_mangle_type(&mut buf, ty);
    buf
}

fn impl_mangle_type(buf: &mut String, ty: &syn::Type) {
    match *ty {
        syn::Type::Slice(ref type_slice) => {
            buf.push_str("slice_");
            impl_mangle_type(buf, &*type_slice.elem);
        },
        syn::Type::Array(ref type_array) => {
            buf.push_str("array");
            impl_mangle_expr(buf, &type_array.len);
            buf.push_str("_");
            impl_mangle_type(buf, &*type_array.elem);
        },
        syn::Type::Ptr(ref type_ptr) => {
            if type_ptr.const_token.is_some() {
                buf.push_str("ptr_const_");
            } else if type_ptr.mutability.is_some() {
                buf.push_str("ptr_mut_");
            } else {
                unreachable!("a pointer is either const or mut");
            }
            impl_mangle_type(buf, &*type_ptr.elem);
        },
        syn::Type::Reference(ref type_reference) => {
            buf.push_str("ref_");
            if type_reference.mutability.is_some() {
                buf.push_str("mut_");
            }
            impl_mangle_type(buf, &*type_reference.elem);
        },
        syn::Type::Path(ref type_path) => {
            assert!(type_path.qself.is_none());
            let last_segment = type_path.path.segments.last().unwrap().into_value();
            buf.push_str(&last_segment.ident.to_string());
        },
        _ => unimplemented!(),
    }
}

fn impl_mangle_expr(_buf: &mut String, _expr: &syn::Expr) {
    unimplemented!()
}
