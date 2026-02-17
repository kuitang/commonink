// Claude Academic Theme
// Warm, serif-heavy design inspired by Claude.ai's aesthetic
// Swap this into the tailwind.config in base.html to activate
//
// Key characteristics:
// - Full serif (Georgia) for headings AND body text
// - Warm cream background (#F5F5F0) instead of cool gray
// - Terracotta orange primary (#ae5630) inspired by Claude brand
// - Gentle, minimal shadows
// - Square/barely-rounded corners for scholarly feel

tailwind.config = {
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                primary: {
                    50: '#fdf5f0',
                    100: '#fbe8dc',
                    200: '#f6cdb5',
                    300: '#f0ab85',
                    400: '#e88453',
                    500: '#c4633a',
                    600: '#ae5630',
                    700: '#924628',
                    800: '#773a22',
                    900: '#62301d',
                },
                success: {
                    50: '#f0f7f0',
                    100: '#dceddc',
                    200: '#b8dbb8',
                    300: '#88c488',
                    400: '#5aab5a',
                    500: '#3d8b3d',
                    600: '#2f6e2f',
                    700: '#275a27',
                    800: '#224922',
                    900: '#1d3d1d',
                },
                error: {
                    50: '#fef2f2',
                    100: '#fee2e2',
                    200: '#fecaca',
                    300: '#fca5a5',
                    400: '#f87171',
                    500: '#ef4444',
                    600: '#dc2626',
                    700: '#b91c1c',
                    800: '#991b1b',
                    900: '#7f1d1d',
                },
                warning: {
                    50: '#fffbeb',
                    100: '#fef3c7',
                    200: '#fde68a',
                    300: '#fcd34d',
                    400: '#fbbf24',
                    500: '#f59e0b',
                    600: '#d97706',
                    700: '#b45309',
                    800: '#92400e',
                    900: '#78350f',
                },
                // Override gray scale with warm tones
                gray: {
                    50: '#F5F5F0',
                    100: '#EBEBDF',
                    200: '#d4d4c8',
                    300: '#b0b0a4',
                    400: '#8d8d82',
                    500: '#6b6a60',
                    600: '#55544c',
                    700: '#403f3a',
                    800: '#2b2a27',
                    900: '#1a1a18',
                },
            },
            borderRadius: {
                'card': '0.25rem',
                'input': '0',
                'badge': '9999px',
                'lg': '0.125rem',
                'xl': '0.25rem',
                '2xl': '0.375rem',
            },
            boxShadow: {
                'card': '0 0.25rem 1.25rem rgba(0,0,0,0.035)',
                'card-hover': '0 0.5rem 2rem rgba(0,0,0,0.06)',
                'subtle': '0 1px 2px 0 rgba(0,0,0,0.03)',
            },
            fontFamily: {
                'display': ['Georgia', "'Times New Roman'", 'serif'],
                'body': ['Georgia', "'Times New Roman'", 'serif'],
            },
        }
    }
}
