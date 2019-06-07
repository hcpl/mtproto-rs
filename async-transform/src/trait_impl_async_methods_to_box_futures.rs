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
        if let Some((_excl_token, ref trait_path, _for_token)) = item_impl.trait_ {
            let trait_lifetimes = path_lifetimes(trait_path);

            for impl_item in &mut item_impl.items {
                if let syn::ImplItem::Method(ref mut impl_item_method) = *impl_item {
                    if impl_item_method.sig.asyncness.is_some() {
                        transform_impl_item_method(impl_item_method, &trait_lifetimes);
                    }
                }
            }

            return quote!(#item_impl);
        }
    }

    macro_error!(item, module_path!(), "can only be used on trait `impl` items");
}


fn path_lifetimes(path: &syn::Path) -> Vec<&syn::Lifetime> {
    path.segments.last().and_then(|last_pair| {
        match last_pair.value().arguments {
            syn::PathArguments::AngleBracketed(ref bracketed) => Some(bracketed),
            syn::PathArguments::None             |
            syn::PathArguments::Parenthesized(_) => None,
        }
    }).iter().flat_map(|bracketed| {
        &bracketed.args
    }).filter_map(|arg| {
        match arg {
            syn::GenericArgument::Lifetime(ref lifetime) => Some(lifetime),
            syn::GenericArgument::Type(_)       |
            syn::GenericArgument::Binding(_)    |
            syn::GenericArgument::Constraint(_) |
            syn::GenericArgument::Const(_)      => None,
        }
    }).collect()
}

fn transform_impl_item_method(
    impl_item_method: &mut syn::ImplItemMethod,
    impl_lifetimes: &[&syn::Lifetime],
) {
    impl_item_method.sig.asyncness = None;

    crate::transform::fn_decl_for_box_pin_future(&mut impl_item_method.sig.decl, impl_lifetimes);

    let orig_block = &impl_item_method.block;
    impl_item_method.block = parse_quote!({ std::boxed::Box::pin({ async move #orig_block }) });
}
