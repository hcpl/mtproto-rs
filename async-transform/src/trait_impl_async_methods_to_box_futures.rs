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
        if item_impl.trait_.is_none() {
            macro_error!(item, module_path!(), "can only be used on trait `impl` items");
        }

        let impl_lifetimes = item_impl.generics.lifetimes()
            .map(|lifetime_def| &lifetime_def.lifetime)
            .collect::<Vec<_>>();

        for impl_item in &mut item_impl.items {
            if let syn::ImplItem::Method(ref mut impl_item_method) = *impl_item {
                if impl_item_method.sig.asyncness.is_some() {
                    transform_impl_item_method(impl_item_method, &impl_lifetimes);
                }
            }
        }

        quote!(#item_impl)
    } else {
        macro_error!(item, module_path!(), "can only be used on trait `impl` items");
    }
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
