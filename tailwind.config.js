/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./website/**/*.{html,js}"],
  theme: {
    extend: {
      translate: {
        calc: 'calc(50vw - 8px)'
      },
      margin: {
        calc: 'calc(50vw - 8px)',
        joinContent: 'calc(50% - 0px)'
      },
      colors: {
        'primary-blue': '#8ECAE6',
        'secondary-blue': '#219EBC',
        'tertiary-blue': '#023047',
        'primary-orange': '#FB8500',
        'secondary-orange': '#FFB703'
      }
    },
  },
  plugins: [],
}