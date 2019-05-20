use quote::quote;
use syn::parse_quote;


pub(crate) fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    if !attr.is_empty() {
        macro_no_args_error!(attr, module_path!());
    }

    if let Ok(mut item_fn) = syn::parse2::<syn::ItemFn>(item.clone()) {
        if item_fn.asyncness.is_none() {
            macro_error!(item_fn, module_path!(), "can only be used on async functions");
        }

        let captures_ident = proc_macro2::Ident::new(
            &format!("__Captures_fn_{}", item_fn.ident),
            proc_macro2::Span::call_site(),
        );

        transform_item_fn(&mut item_fn, &captures_ident);

        let vis = &item_fn.vis;

        quote! {
            #vis trait #captures_ident<'a> {}
            impl<'a, T> #captures_ident<'a> for T {}

            #item_fn
        }
    } else {
        macro_error!(item, module_path!(), "can only be used on async functions");
    }
}


fn transform_item_fn(
    item_fn: &mut syn::ItemFn,
    captures_ident: &proc_macro2::Ident,
) {
    item_fn.asyncness = None;

    crate::transform::fn_decl_for_impl_future(&mut item_fn.decl, &[], captures_ident);

    let orig_block = &item_fn.block;
    item_fn.block = parse_quote!({ async move #orig_block });
}
