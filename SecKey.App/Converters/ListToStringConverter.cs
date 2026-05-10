using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using System.Windows.Data;

namespace SecKey.App.Converters
{
    public class ListToStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is null) return string.Empty;
            if (value is string s) return s;
            if (value is IEnumerable enumerable)
            {
                var items = enumerable.Cast<object?>()
                    .Where(x => x != null)
                    .Select(x => x!.ToString())
                    .Where(x => !string.IsNullOrWhiteSpace(x));
                return string.Join(", ", items);
            }
            return value.ToString() ?? string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }
}
