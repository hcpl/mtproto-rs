use syn::Token;


pub(crate) struct ItemTraitWithAsyncMethods(pub(crate) syn::ItemTrait);

impl syn::parse::Parse for ItemTraitWithAsyncMethods {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        parse_item_trait_with_async_methods(input).map(Self)
    }
}


fn parse_item_trait_with_async_methods(
    input: syn::parse::ParseStream,
) -> syn::Result<syn::ItemTrait> {
    let attrs = input.call(syn::Attribute::parse_outer)?;
    let vis: syn::Visibility = input.parse()?;
    let unsafety: Option<Token![unsafe]> = input.parse()?;
    let auto_token: Option<Token![auto]> = input.parse()?;
    let trait_token: Token![trait] = input.parse()?;
    let ident: proc_macro2::Ident = input.parse()?;
    let mut generics: syn::Generics = input.parse()?;

    let colon_token: Option<Token![:]> = input.parse()?;

    let mut supertraits = syn::punctuated::Punctuated::new();
    if colon_token.is_some() {
        loop {
            supertraits.push_value(input.parse()?);
            if input.peek(Token![where]) || input.peek(syn::token::Brace) {
                break;
            }
            supertraits.push_punct(input.parse()?);
            if input.peek(Token![where]) || input.peek(syn::token::Brace) {
                break;
            }
        }
    }

    generics.where_clause = input.parse()?;

    let content;
    let brace_token = syn::braced!(content in input);
    let mut items = Vec::new();
    while !content.is_empty() {
        items.push(content.call(parse_trait_item_with_async_methods)?);
    }

    Ok(syn::ItemTrait {
        attrs,
        vis,
        unsafety,
        auto_token,
        trait_token,
        ident,
        generics,
        colon_token,
        supertraits,
        brace_token,
        items,
    })
}

fn parse_trait_item_with_async_methods(
    input: syn::parse::ParseStream,
) -> syn::Result<syn::TraitItem> {
    let ahead = input.fork();
    ahead.call(syn::Attribute::parse_outer)?;

    let lookahead = ahead.lookahead1();
    if lookahead.peek(Token![const]) {
        ahead.parse::<Token![const]>()?;
        let lookahead = ahead.lookahead1();
        if lookahead.peek(syn::Ident) {
            input.parse().map(syn::TraitItem::Const)
        } else if lookahead.peek(Token![unsafe])
            || lookahead.peek(Token![async])
            || lookahead.peek(Token![extern])
            || lookahead.peek(Token![fn])
        {
            input.call(parse_trait_item_method_with_async).map(syn::TraitItem::Method)
        } else {
            Err(lookahead.error())
        }
    } else if lookahead.peek(Token![unsafe])
        || lookahead.peek(Token![async])
        || lookahead.peek(Token![extern])
        || lookahead.peek(Token![fn])
    {
        input.call(parse_trait_item_method_with_async).map(syn::TraitItem::Method)
    } else if lookahead.peek(Token![type]) {
        input.parse().map(syn::TraitItem::Type)
    } else if lookahead.peek(syn::Ident)
        || lookahead.peek(Token![self])
        || lookahead.peek(Token![super])
        || lookahead.peek(Token![extern])
        || lookahead.peek(Token![crate])
        || lookahead.peek(Token![::])
    {
        input.parse().map(syn::TraitItem::Macro)
    } else {
        Err(lookahead.error())
    }
}

fn parse_trait_item_method_with_async(
    input: syn::parse::ParseStream,
) -> syn::Result<syn::TraitItemMethod> {
    let outer_attrs = input.call(syn::Attribute::parse_outer)?;
    let constness: Option<Token![const]> = input.parse()?;
    let unsafety: Option<Token![unsafe]> = input.parse()?;
    let asyncness: Option<Token![async]> = input.parse()?;
    let abi: Option<syn::Abi> = input.parse()?;
    let fn_token: Token![fn] = input.parse()?;
    let ident: proc_macro2::Ident = input.parse()?;
    let generics: syn::Generics = input.parse()?;

    let content;
    let paren_token = syn::parenthesized!(content in input);
    let inputs = content.parse_terminated(<syn::FnArg as syn::parse::Parse>::parse)?;

    let output: syn::ReturnType = input.parse()?;
    let where_clause: Option<syn::WhereClause> = input.parse()?;

    let lookahead = input.lookahead1();
    let (brace_token, inner_attrs, stmts, semi_token) = if lookahead.peek(syn::token::Brace) {
        let content;
        let brace_token = syn::braced!(content in input);
        let inner_attrs = content.call(syn::Attribute::parse_inner)?;
        let stmts = content.call(syn::Block::parse_within)?;
        (Some(brace_token), inner_attrs, stmts, None)
    } else if lookahead.peek(Token![;]) {
        let semi_token: Token![;] = input.parse()?;
        (None, Vec::new(), Vec::new(), Some(semi_token))
    } else {
        return Err(lookahead.error());
    };

    let mut attrs = outer_attrs;
    attrs.extend(inner_attrs);

    Ok(syn::TraitItemMethod {
        attrs,
        sig: syn::MethodSig {
            constness,
            unsafety,
            asyncness,
            abi,
            ident,
            decl: syn::FnDecl {
                fn_token,
                paren_token,
                inputs,
                output,
                variadic: None,
                generics: syn::Generics {
                    where_clause,
                    ..generics
                },
            },
        },
        default: brace_token.map(|brace_token| syn::Block {
            brace_token,
            stmts,
        }),
        semi_token,
    })
}
