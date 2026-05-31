#ifdef _MSC_VER
#pragma warning(disable:4244; disable:4267; disable:4146; disable:4018)
#endif //_MSC_VER
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wswitch"
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wvarargs"
#ifdef __MAC__
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif // __MAC__
#pragma GCC diagnostic push

//temporary fix for gcc 13.1.1 and IDA81
#include <cstdint>
#endif // __GNUC__

// pro.h uses std::is_pod, which libc++ only declares once <type_traits> has
// been included (it is deprecated, not removed). Pull it in here — before any
// <pro.h> include that follows this header — so the symbol is in scope.
#include <type_traits>
