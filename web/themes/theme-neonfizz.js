// Neon Fizz Theme
// Bold, energetic design mashup of Discord's dark surfaces + Fly.io's purple gradients
// Swap this into the tailwind.config in base.html to activate
//
// Key characteristics:
// - Dark mode default with Discord-style layered gray surfaces
// - Vivid purple primary (#7c3aed) inspired by Fly.io's gradient palette
// - Discord's semantic status colors (green/red/yellow)
// - Monospace display font (SF Mono) for techy hacker feel
// - Extra-rounded cards (1.25rem) for bubbly, pillowy aesthetic
// - Subtle shadows on dark, more pronounced on light

tailwind.config = {
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                primary: {
                    50: '#f5f3ff',
                    100: '#ede9fe',
                    200: '#ddd6fe',
                    300: '#c4b5fd',
                    400: '#a78bfa',
                    500: '#8b5cf6',
                    600: '#7c3aed',
                    700: '#6d28d9',
                    800: '#5b21b6',
                    900: '#4c1d95',
                },
                success: {
                    50: '#ecfdf5',
                    100: '#d1fae5',
                    200: '#a7f3d0',
                    300: '#6ee7b7',
                    400: '#43B581',
                    500: '#23A55A',
                    600: '#16a34a',
                    700: '#15803d',
                    800: '#166534',
                    900: '#14532d',
                },
                error: {
                    50: '#fef2f2',
                    100: '#fee2e2',
                    200: '#fecaca',
                    300: '#fca5a5',
                    400: '#f87171',
                    500: '#F23F43',
                    600: '#ED4245',
                    700: '#b91c1c',
                    800: '#991b1b',
                    900: '#7f1d1d',
                },
                warning: {
                    50: '#fffbeb',
                    100: '#fef3c7',
                    200: '#fde68a',
                    300: '#fcd34d',
                    400: '#FAA61A',
                    500: '#F0B232',
                    600: '#d97706',
                    700: '#b45309',
                    800: '#92400e',
                    900: '#78350f',
                },
                // Override gray scale with Discord dark surfaces
                gray: {
                    50: '#f2f3f5',
                    100: '#ebedef',
                    200: '#d4d7dc',
                    300: '#b9bbbe',
                    400: '#949BA4',
                    500: '#80848E',
                    600: '#4E5058',
                    700: '#383A40',
                    800: '#313338',
                    900: '#2B2D31',
                    950: '#1E1F22',
                },
            },
            borderRadius: {
                'card': '1.25rem',
                'input': '0.75rem',
                'badge': '9999px',
                'lg': '1rem',
                'xl': '1.25rem',
                '2xl': '1.5rem',
            },
            boxShadow: {
                'card': '0 1px 0 rgba(4,4,5,0.2), 0 1.5px 0 rgba(6,6,7,0.05), 0 2px 0 rgba(4,4,5,0.05)',
                'card-hover': '0 4px 4px rgba(0,0,0,0.16)',
                'subtle': '0 1px 0 rgba(4,4,5,0.1)',
            },
            fontFamily: {
                'display': ["'SF Mono'", 'ui-monospace', 'Consolas', 'monospace'],
                'body': ['system-ui', '-apple-system', 'sans-serif'],
            },
        }
    }
}
