function convert() {
    const input = document.getElementById('inputText').value;
    const valfrom = document.getElementById('conversionfrom').value;
    const valto = document.getElementById('conversionto').value;
    const gambar = document.getElementById('gambar');
    const easteregg = document.getElementById('easteregg');
    const urleasteregg = document.getElementById('eastereggurl');
    const type = valfrom + "To" + valto;
    let output = '';

    try {
        switch (type) {
            case 'TextToBinary':
                output = input.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
                break;
            case 'BinaryToText':
                output = input.split(' ').map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
                break;
            case 'TextToHexadecimal':
                output = input.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
                break;
            case 'HexadecimalToText':
                output = input.trim().split(/\s+/).map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
                break;
            case 'TextToOctal':
                output = input.split('').map(char => char.charCodeAt(0).toString(8).padStart(3, '0')).join(' ');
                break;
            case 'OctalToText':
                output = input.trim().split(/\s+/).map(oct => String.fromCharCode(parseInt(oct, 8))).join('');
                break;
            // Text to Base64
            case 'TextToBase64':
                output = btoa(unescape(encodeURIComponent(input)));
                break;
            // Base64 to Text
            case 'Base64ToText':
                output = decodeURIComponent(escape(atob(input)));
                break;
            // Decimal
            case 'DecimalToBinary':
                output = parseInt(input, 10).toString(2);
                break;
            case 'DecimalToOctal':
                output = parseInt(input, 10).toString(8);
                break;
            case 'DecimalToHexadecimal':
                output = parseInt(input, 10).toString(16);
                break;
            case 'DecimalToDecimal':
                output = parseInt(input, 10).toString(10);
                break;
            // Binary
            case 'BinaryToBinary':
                output = parseInt(input, 2).toString(2);
                break;
            case 'BinaryToOctal':
                output = parseInt(input, 2).toString(8);
                break;
            case 'BinaryToHexadecimal':
                output = parseInt(input, 2).toString(16);
                break;
            case 'BinaryToDecimal':
                output = parseInt(input, 2).toString(10);
                break;
            // Octal
            case 'OctalToBinary':
                output = parseInt(input, 8).toString(2);
                break;
            case 'OctalToOctal':
                output = parseInt(input, 8).toString(8);
                break;
            case 'OctalToHexadecimal':
                output = parseInt(input, 8).toString(16);
                break;
            case 'OctalToDecimal':
                output = parseInt(input, 8).toString(10);
                break;
            //Hexadecimal
            case 'HexadecimalToBinary':
                output = parseInt(input, 16).toString(2);
                break;
            case 'HexadecimalToOctal':
                output = parseInt(input, 16).toString(8);
                break;
            case 'HexadecimalToHexadecimal':
                output = parseInt(input, 16).toString(16);
                break;
            case 'HexadecimalToDecimal':
                output = parseInt(input, 16).toString(10);
                break;
        }
        if (output === 'Potato'){
            gambar.src = "../assets/Easter_egg_image/img1.png";
            urleasteregg.href = "https://youtu.be/dQw4w9WgXcQ?si=ehfgKuBv50yu8aur";
            easteregg.innerText = "ⓘ You've Been Potatoed :)";
        }
        if (output === '100000001000000001'){
            gambar.src = "../assets/Easter_egg_image/sawit.jpg";
            urleasteregg.href = "https://www.youtube.com/watch?v=i2JQMDgNOa8";
            easteregg.innerText = "ⓘ Just Sa WIT :)";
        }
    } catch (e) {
        output = 'Gagal mengkonversi! Pastikan format input sudah benar.';
    }

    document.getElementById('result').innerText = output;
}