import matplotlib.pyplot as plt
import numpy as np

# Dados extraídos da tabela (em segundos)
caracteres = np.arange(3, 16)

# Conversões: 6min = 360s | 2h 32min = 9120s | 2.74 dias = 236736s | 71 dias = 6134400s | 5.08 anos = 160168320s
estimativa = [6, 6, 6, 6, 6, 6, 7, 19, 360, 9120, 236736, 6134400, 160168320]

# 3 min 7.7 s = 187.7s
decorrido = [1.7, 1.7, 1.7, 1.7, 3.7, 3.7, 3.7, 10.7, 187.7, 18.0, None, None, None]

plt.figure(figsize=(10, 6))

# Plotagem em escala logarítmica (essencial para a diferença extrema de tempo)
plt.plot(caracteres, estimativa, marker='s', color='red', linestyle='-', linewidth=2, label='Estimativa na GPU')
plt.plot(caracteres[:10], decorrido[:10], marker='o', color='blue', linestyle='-', linewidth=2, label='Tempo Decorrido Real')

plt.yscale('log')
plt.xticks(caracteres)
plt.title('Tempo de Busca de Senha vs Comprimento (Escala Logarítmica)')
plt.xlabel('Quantidade de Caracteres no Total')
plt.ylabel('Tempo em Segundos (Log)')
plt.grid(True, which="both", ls="--", alpha=0.5)
plt.legend()
plt.tight_layout()

# Salva a imagem
plt.savefig('grafico_criptoanalise.png', dpi=300)
plt.show()
