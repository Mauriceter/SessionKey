# Recherche de clef de Chiffrement
_De Bats Joachim_

## Objectif :
Lorsque qu'un malware accède à internet pour récuperer des données par exemple, une session encryptée se crée. Lors du protocole d'échange, un nonce (nombre pseudo-aléatoire)  est transmis qui permet d'éviter une attaque par rejeu, c'est à dire de réutiliser une session précédente. Ce projet, encadré par M. Guillaume Bonfante, a pour objectif d'aller chercher en mémoire ce nonce afin de pouvoir le manipuler à notre guise et enventuellement réussir à réutiliser une session précédente. Les recherches se sont basé autour du programme curl dont le code source est facilement accessible et qui ne présentait pas de danger contrairement à un malware.

## Ressource :

Les démarches sont détaillés dans le document [AnalyseCurl.md](https://github.com/Mauriceter/SessionKey/blob/main/AnalyseCurl.md) et les slides de la présentation sont accessible [ici](https://docs.google.com/presentation/d/1QYbbTON92y1H5w6KDX8O2pdMYd0NBbCQj25Ga6Jd2X8/edit?usp=sharing).

