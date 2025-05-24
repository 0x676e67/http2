macro_rules! define_enum_with_values {
    (
        $(#[$enum_meta:meta])*
        @U16
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $value:expr,
            )*
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value,
            )*
            Unknown(u16),
        }

        impl From<$name> for u16 {
            fn from(src: $name) -> u16 {
                match src {
                    $(
                        $name::$variant => $value,
                    )*
                    $name::Unknown(id) => id,
                }
            }
        }

        impl From<u16> for $name {
            fn from(id: u16) -> $name {
                match id {
                    $(
                        $value => $name::$variant,
                    )*
                    _ => $name::Unknown(id),
                }
            }
        }
    };

    (
        $(#[$enum_meta:meta])*
        @U8
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $value:expr,
            )*
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        #[repr(u8)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value,
            )*
        }

        impl From<$name> for u8 {
            fn from(src: $name) -> u8 {
                match src {
                    $(
                        $name::$variant => $value,
                    )*
                }
            }
        }
    };
}
