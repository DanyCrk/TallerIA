Entrega Ejercicio: Inteligencia Artificial aplicada al Desarrollo de Software


Para este taller se genero el spec, que posteriormente se le paso a Claude y a Deepseek para comparar sus respuestas.
Dichas respuestas se encuentran en cada carpeta que hay en el repositorio.

Haciendo una comparativa para ver cual IA tuvo mejor desempeño en la tarea asignada se obtiene lo siguiente:

Pruebas y cobertura
En cuanto a Suite completa, aislamiento, fixtures, Claude tuvo un mejor desempeño por sobre Deepseek.

---
Claude gana en criterios de producción real: tests verificados, código ejecutable sin modificaciones y mayor cobertura del SPEC. 
DeepSeek produce una arquitectura más limpia en algunos aspectos (CORS, HTTPBearer nativo, logging más granular por método) pero entrega código incompleto
ademas sus pruebas usan un cliente sin base de datos de prueba aislada, y varios archivos clave faltan por completo.
En cuanto a código funcional y verificado Claude es mejor.

Claude gana en que el código está verificado, 21 pruebas que pasan, 91.7% de cobertura medida. 
El código de DeepSeek tiene tests escritos pero no hay conftest.py, ni base de datos de prueba aislada, ni migración Alembic, ni session.py.
En la práctica, no funcionan sin trabajo adicional.
Y agrega el claim jti en los JWT para que la rotación de tokens funcione incluso si dos tokens se generan en el mismo segundo, un edge case real que
DeepSeek no cubre.

DeepSeek tiene dos ventajas arquitectónicas Primero, usa HTTPBearer de FastAPI como dependency en lugar de parsear manualmente el header
Authorization, es la forma idiomática y genera documentación OpenAPI automática con el candado en Swagger. 
Segundo, su logging en auth_service.py es más granular ya que registra eventos específicos por función con el user_id incluido, 
lo que es mejor para auditoría en producción. 
También detecta reuso de token con una respuesta más agresiva, lo cual es una práctica de seguridad defensiva válida.
Lo que DeepSeek hace y claude no, es que el middleware CORS esta configurado desde variables de entorno, 
la separación de dependencies.py como archivo propio, y el campo ALGORITHM en settings 





