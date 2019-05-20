extern crate proc_macro;


macro_rules! syn_compile_error {
    ($obj:ident, $message:expr) => {{
        return syn::Error::new_spanned($obj, $message).to_compile_error();
    }};
}

macro_rules! macro_error {
    ($obj:ident, $module_path:expr, $message:expr) => {
        syn_compile_error!($obj, concat!("#[", $module_path, "] ", $message));
    }
}

macro_rules! macro_no_args_error {
    ($obj:ident, $module_path:expr) => {
        macro_error!($obj, $module_path, "doesn't take arguments")
    }
}

mod item_trait_with_async_methods;
pub(crate) use item_trait_with_async_methods::ItemTraitWithAsyncMethods;

mod transform;


mod async_fn_to_impl_future;
mod impl_async_methods_to_impl_futures;
mod trait_decl_async_methods_to_box_futures;
mod trait_impl_async_methods_to_box_futures;


#[proc_macro_attribute]
pub fn async_fn_to_impl_future(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    async_fn_to_impl_future::expand(attr.into(), item.into()).into()
}

#[proc_macro_attribute]
pub fn impl_async_methods_to_impl_futures(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    impl_async_methods_to_impl_futures::expand(attr.into(), item.into()).into()
}

#[proc_macro_attribute]
pub fn trait_decl_async_methods_to_box_futures(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    trait_decl_async_methods_to_box_futures::expand(attr.into(), item.into()).into()
}

#[proc_macro_attribute]
pub fn trait_impl_async_methods_to_box_futures(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    trait_impl_async_methods_to_box_futures::expand(attr.into(), item.into()).into()
}
