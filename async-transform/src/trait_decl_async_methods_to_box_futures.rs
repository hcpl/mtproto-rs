use quote::quote;
use syn::parse_quote;


pub(crate) fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    if !attr.is_empty() {
        macro_no_args_error!(attr, module_path!());
    }

    if let Ok(item_trait_wam) = syn::parse2::<crate::ItemTraitWithAsyncMethods>(item.clone()) {
        let mut item_trait = item_trait_wam.0;

        let trait_lifetimes = item_trait.generics.lifetimes()
            .map(|lifetime_def| &lifetime_def.lifetime)
            .collect::<Vec<_>>();

        for trait_item in &mut item_trait.items {
            if let syn::TraitItem::Method(ref mut trait_item_method) = *trait_item {
                if trait_item_method.sig.asyncness.is_some() {
                    transform_trait_item_method(trait_item_method, &trait_lifetimes);
                }
            }
        }

        quote!(#item_trait)
    } else {
        macro_error!(item, module_path!(), "can only be used on trait declarations");
    }
}


fn transform_trait_item_method(
    trait_item_method: &mut syn::TraitItemMethod,
    trait_lifetimes: &[&syn::Lifetime],
) {
    trait_item_method.sig.asyncness = None;

    crate::transform::fn_decl_for_box_pin_future(&mut trait_item_method.sig.decl, trait_lifetimes);

    if let Some(ref mut orig_block) = trait_item_method.default {
        trait_item_method.default = Some(parse_quote!({ std::boxed::Box::pin({ async move #orig_block }) }));
    }
}
