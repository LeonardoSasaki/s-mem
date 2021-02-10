Simple external process memory manipulation class for cheat &amp; malware dev

<details><summary><h2>🌐 EN-US</h2></summary>
<h2> s-mem </h2><p>
A minimalistic open source class for memory manipulation using WinAPI for both malware and cheat dev. Note that this is not a magic solution agaisn't antivirus / anticheats, since handle creation can be blocked and WPM/RPM can be monitored. </p>

This class supports:
  * Class initialization from process name, PID or from existing handles
  * Simplified WinAPI calls
  * Memory read/write
  * Module querying
  * Changing target process without re-creating a class instance
  * Proper verification of class initialization (whether the target process was found or not) 
  * Fast signature scanning with one RPM
  * Automatic handle closure
  
  
#### ***Side note: i do not support cheating in multiplayer games, do not expect being magically undetected using this class. This is just a lightweight minimal implementation of WinAPI for external memory manipulation.*** </details>

<details><summary><h2>🌐 PT-BR</h2></summary>
<h2> s-mem </h2><p>
Uma classe minimalística de código aberto para manipulação de memória utilizando a WinAPI para criação de malware & cheats. Note que isto não é uma solução mágica contra antivírus / anticheats, visto que criação de handles podem ser bloqueadas e WPM/RPM monitoradas.</p

Esta classe suporta:
  * Inicialização de classe apartir do nome do processo, PID ou através de uma handle já existente
  * Chamadas da WinAPI simplificadas
  * Leitura/Escritura de memória
  * Query de módulos
  * Alterar processo alvo sem necessitar de uma nova instância de classe
  * Verificação de inicialização da classe (se o processo alvo foi achado ou não)
  * Scaneamento de signatura rápida utilizando 1 RPM
  * Fechamento de handle automática
  
  
#### ***Nota: Eu não apoio o cheating em jogos multiplayer, não espere ficar mágicamente indetectado usando esta classe. Esta é só uma implementação mínima da WinAPI para manipular memória externamente.***
