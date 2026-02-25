#!/bin/bash
# Automação Silver Bullet - Ferrari Edition

echo "🚀 Preparando o envio para o GitHub..."

# 1. Adiciona tudo (incluindo o README e .gitignore)
git add .

# 2. Pergunta pela mensagem do commit (ou usa data/hora se deixares vazio)
read -p "📝 Mensagem do commit (Enter para 'Update Automático'): " msg
if [ -z "$msg" ]; then
  msg="Update: $(date +'%Y-%m-%d %H:%M:%S')"
fi

# 3. Faz o commit
git commit -m "$msg"

# 4. Sincroniza com o GitHub (evita aquele erro de rejected)
echo "🔄 Sincronizando..."
git pull origin main --rebase

# 5. Envia
echo "📤 Enviando..."
git push origin main

# 6. Bónus: Perguntar se quer compilar e gravar
read -p "🔥 Deseja compilar e gravar no Cardputer agora? (s/n): " flash
if [ "$flash" == "s" ]; then
  # Garante que o ambiente IDF está ativo
  . $HOME/esp/esp-idf/export.sh
  idf.py build flash monitor
fi

echo "✅ Concluído!"
