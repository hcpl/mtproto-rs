use syn::parse_quote;


pub(crate) fn fn_decl_for_impl_future(
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

    let (r_arrow, mut impl_future): (_, syn::TypeImplTrait) = match output {
        syn::ReturnType::Default => {
            (Default::default(), parse_quote!(impl core::future::Future<Output = ()>))
        },
        syn::ReturnType::Type(ref r_arrow, ref ty) => {
            (*r_arrow, parse_quote!(impl core::future::Future<Output = #ty>))
        },
    };

    let mut fn_arg_transform = FnArgTransform {
        lifetime_counter: 0,
        generics,
        res_lifetime: &res_lifetime,
        impl_future: Some(&mut impl_future),
        captures_ident: Some(captures_ident),
    };

    for impl_lifetime in impl_lifetimes {
        fn_arg_transform.bind_lifetime(impl_lifetime);
    }

    for input in inputs {
        syn::visit_mut::visit_fn_arg_mut(&mut fn_arg_transform, input);
    }

    impl_future.bounds.push(parse_quote!(#res_lifetime));
    *output = parse_quote!(#r_arrow #impl_future);
}

pub(crate) fn fn_decl_for_box_pin_future(
    fn_decl: &mut syn::FnDecl,
    trait_lifetimes: &[&syn::Lifetime],
) {
    let syn::FnDecl {
        ref mut generics,
        ref mut inputs,
        ref mut output,
        ..
    } = *fn_decl;

    let res_lifetime = syn::Lifetime::new("'__res", proc_macro2::Span::call_site());
    generics.params.push(parse_quote!(#res_lifetime));

    let mut fn_arg_transform = FnArgTransform {
        lifetime_counter: 0,
        generics,
        res_lifetime: &res_lifetime,
        impl_future: None,
        captures_ident: None,
    };

    for trait_lifetime in trait_lifetimes {
        fn_arg_transform.bind_lifetime(trait_lifetime);
    }

    for input in inputs {
        syn::visit_mut::visit_fn_arg_mut(&mut fn_arg_transform, input);
    }

    *output = match output {
        syn::ReturnType::Default => {
            parse_quote!(
                ->
                core::pin::Pin<
                    std::boxed::Box<
                        dyn core::future::Future<Output = ()> +
                        core::marker::Send +
                        #res_lifetime
                    >
                >
            )
        },
        syn::ReturnType::Type(ref r_arrow, ref ty) => {
            parse_quote!(
                #r_arrow
                core::pin::Pin<
                    std::boxed::Box<
                        dyn core::future::Future<Output = #ty> +
                        core::marker::Send +
                        #res_lifetime
                    >
                >
            )
        },
    };
}


struct FnArgTransform<'ast> {
    lifetime_counter: usize,
    generics: &'ast mut syn::Generics,
    res_lifetime: &'ast syn::Lifetime,
    impl_future: Option<&'ast mut syn::TypeImplTrait>,
    captures_ident: Option<&'ast proc_macro2::Ident>,
}

impl<'ast> FnArgTransform<'ast> {
    fn countered_lifetime(&mut self) -> syn::Lifetime {
        let lifetime_str = format!("'__{}", self.lifetime_counter);
        let lifetime = syn::Lifetime::new(&lifetime_str, proc_macro2::Span::call_site());

        self.lifetime_counter += 1;

        lifetime
    }

    pub(crate) fn bind_lifetime(&mut self, lifetime: &syn::Lifetime) {
        let res_lifetime = self.res_lifetime;
        self.generics.make_where_clause().predicates.push(parse_quote!(#lifetime: #res_lifetime));

        match (self.impl_future.as_mut(), self.captures_ident.as_ref()) {
            (Some(ref mut impl_future), Some(ref captures_ident)) => {
                impl_future.bounds.push(parse_quote!(#captures_ident<#lifetime>));
            },
            (None, None) => (),
            _ => unreachable!("`impl_future` and `captures_ident` must be either both `Some(...)` or both `None`"),
        }
    }
}

impl<'ast> syn::visit_mut::VisitMut for FnArgTransform<'ast> {
    fn visit_arg_self_ref_mut(&mut self, arg_self_ref: &mut syn::ArgSelfRef) {
        let lifetime = arg_self_ref.lifetime.take().unwrap_or_else(|| {
            let new_lifetime = self.countered_lifetime();
            self.generics.params.push(parse_quote!(#new_lifetime));
            new_lifetime
        });

        self.bind_lifetime(&lifetime);
        arg_self_ref.lifetime = Some(lifetime);
    }

    fn visit_type_reference_mut(&mut self, type_reference: &mut syn::TypeReference) {
        let lifetime = type_reference.lifetime.take().unwrap_or_else(|| {
            let new_lifetime = self.countered_lifetime();
            self.generics.params.push(parse_quote!(#new_lifetime));
            new_lifetime
        });

        self.bind_lifetime(&lifetime);
        type_reference.lifetime = Some(lifetime);
    }

    fn visit_lifetime_mut(&mut self, lifetime: &mut syn::Lifetime) {
        self.bind_lifetime(lifetime);
    }
}
