document.addEventListener('DOMContentLoaded', function() {
    
    // ---------------------------------------------
    // A) FLASH MESAJ OTOMATİK GİZLEME (UX İYİLEŞTİRMESİ)
    // ---------------------------------------------
    const flashMessagesContainer = document.querySelector('.flash-messages-container');
    
    if (flashMessagesContainer) {
        // Mesaj kutusunu 5 saniye sonra gizle ve kaldır
        setTimeout(() => {
            flashMessagesContainer.style.transition = 'opacity 1s ease-out';
            flashMessagesContainer.style.opacity = '0'; // Görünmez yap

            // 1 saniye sonra (animasyon bittikten sonra) DOM'dan kaldır
            setTimeout(() => {
                flashMessagesContainer.remove();
            }, 1000); 

        }, 5000); // 5 saniye sonra başlat
    }
    
    // ---------------------------------------------
    // C) YAPAY ZEKA CHATBOT'U AÇMA/KAPAMA
    // ---------------------------------------------
    const chatButton = document.querySelector('.chat-fab-button');
    const chatPanel = document.querySelector('.chatbot-panel-container'); // Menü penceresi

    if (chatButton && chatPanel) {
        chatButton.addEventListener('click', function() {
            
            // 1. Butonu gizle/göster (Mevcut davranış: Buton kayboluyor)
            // Bu satır, tıklayınca butonun kaybolmasını sağlayan satır. 
            // Eğer tuş kaybolup gelmesini istiyorsanız, bu satırı kullanın.
            chatButton.style.display = 'none'; 

            // 2. Menü panelini görünür yap
            // Panel şu an gizli olmalı (Örn: CSS'te display: none; veya opacity: 0;)
            chatPanel.style.display = 'block'; // Veya 'flex'

            // KRİTİK NOT: Eğer paneliniz CSS'te bir 'is-open' sınıfı ile açılıyorsa, 
            // yukarıdaki satır yerine şunu kullanın:
            // chatPanel.classList.toggle('is-open'); 
        });
    }
    // ---------------------------------------------
    // B) ANA SAYFA TERMINAL YAZMA ANİMASYONU
    // ---------------------------------------------

    // Sadece index.html'de çalışmasını sağlamak için kontrol ekle
    if (document.getElementById('animated-code')) {
        
        const codeElement = document.getElementById('animated-code');
        const fullCode =
        `# Python ile Basit Bir Siber Güvenlik Kontrolü
import socket

def port_tarama(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        sonuc = s.connect_ex((host, port))
        if sonuc == 0:
            print(f"[AÇIK] Port {port}")
        else:
            print(f"[KAPALI] Port {port}")
        s.close()
    except:
        pass

# Örnek Kullanım:
# port_tarama("google.com", 80)
# port_tarama("127.0.0.1", 22)`;

        let index = 0;

        function typeCode() {
            if (index < fullCode.length) {
                // Yeni satır karakterini atla, animasyonu hızlandır
                if (fullCode.charAt(index) === '\n') {
                    codeElement.innerHTML += '\n';
                    index++;
                }
                codeElement.innerHTML += fullCode.charAt(index);
                index++;
                setTimeout(typeCode, 10); // Yazma hızını ayarlar (ms)
            } else {
                // Tüm kod yazıldıktan sonra Highlight.js ile renklendir
                if (window.hljs) {
                    hljs.highlightElement(codeElement); 
                }
            }
        }

        typeCode();
    }
});