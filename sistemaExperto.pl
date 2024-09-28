:- use_module(library(csv)).
:- use_module(library(apply)).
:- dynamic vulnerabilidad/7.
:- dynamic exploit/16.
:- dynamic exploits_cargados/0.

% Cargar las vulnerabilidades desde el archivo CSV
cargar_vulnerabilidades(File) :-
    catch(
        csv_read_file(File, Filas, [functor(fila), strip(true)]),
        Error,
        (format('Error al cargar vulnerabilidades desde el archivo ~w: ~w~n', [File, Error]), fail)
    ),
    (   Filas = [_Encabezado|Datos] ->
        assert_vulnerabilidades(Datos)
    ;   format('El archivo ~w está vacío o no tiene el formato correcto.~n', [File])
    ).

% Afirmar las vulnerabilidades en la base de datos
assert_vulnerabilidades([]).
assert_vulnerabilidades([Fila|Resto]) :-
    Fila = fila(Name, Status, Description, References, Phase, Votes, Comments),
    assert(vulnerabilidad(Name, Status, Description, References, Phase, Votes, Comments)),
    assert_vulnerabilidades(Resto).

% Cargar los exploits desde el archivo CSV
cargar_exploits(File) :-
    catch(
        csv_read_file(File, Filas, [functor(fila), strip(true)]),
        Error,
        (format('Error al cargar exploits desde el archivo ~w: ~w~n', [File, Error]), fail)
    ),
    (   Filas = [_Encabezado|Datos] ->
        assert_exploits(Datos),
        assert(exploits_cargados)
    ;   format('El archivo ~w está vacío o no tiene el formato correcto.~n', [File])
    ).

% Afirmar los exploits en la base de datos
assert_exploits([]).
assert_exploits([Fila|Resto]) :-
    Fila = fila(_, File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Codes, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl),
    (   var(Codes) ->
        true
    ;   atomic_list_concat(ListaCodigos, ';', Codes),
        procesar_codigos(File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, ListaCodigos, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl)
    ),
    assert_exploits(Resto).

% Procesar la lista de códigos y solo insertar aquellos que contienen "CVE"
procesar_codigos(_, _, _, _, _, _, _, _, _, _, [], _, _, _, _, _).
procesar_codigos(File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, [Codigo|Resto], Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl) :-
    (   sub_string(Codigo, _, _, _, "CVE") ->
        assert(exploit(_, File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Codigo, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl))
    ;   true
    ),
    procesar_codigos(File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Resto, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl).

% Consultar vulnerabilidades por nombre
consultar_vulnerabilidad_por_nombre(Nombre) :-
    format('Buscando vulnerabilidad con el nombre: ~w~n', [Nombre]),  % Imprime lo que está buscando
    atom_string(NombreAtom, Nombre),  % Convierte el string a átomo para la comparación
    (   vulnerabilidad(NombreAtom, Status, Description, References, Phase, Votes, Comments) ->
        format('--- Información de la Vulnerabilidad ---~n', []),
        format('Nombre: ~w~nEstado: ~w~nDescripción: ~w~nReferencias: ~w~nFase: ~w~nVotos: ~w~nComentarios: ~w~n',
            [NombreAtom, Status, Description, References, Phase, Votes, Comments]),
        % Si se encuentra la vulnerabilidad, buscar exploits asociados
        atom_string(Atom, NombreAtom),
        consultar_exploits_por_codigo(Atom),
    ;   format('No se encontró la vulnerabilidad ~w.~n', [NombreAtom])
    ).

% Predicado para buscar exploits asociados a una vulnerabilidad
buscar_exploit_por_vulnerabilidad(Vulnerabilidad) :-
    (   exploit(_, _, _, _, _, _, _, _, _, _, _, Vulnerabilidad, _, _, _, _, _) ->  % Si es exploit/17
        format('--- Exploit encontrado ---~n', []),
        format('Código del Exploit: ~w~n', [Vulnerabilidad])
    ;   format('No se encontró ningún exploit para la vulnerabilidad ~w.~n', [Vulnerabilidad])
    ).


% Consultar exploit por código
consultar_exploit_por_codigo(Codigo) :-
    writeln(Codigo),  % Imprime el código para depuración
    findall(exploit(File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Codigo, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl),
            exploit(_, File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Codigo, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl),
            Resultados),
    (   Resultados \= []
    ->  format('--- Información del Exploit ---~n'),
        consultar_exploits_por_codigo(Codigo)
            ;   format('No se encontró ningún exploit con el código ~w.~n', [Codigo])
    ).


% Mostrar todos los exploits en la base de datos de manera legible
mostrar_exploits :-
    format('--- Lista de Exploits ---~n'),
    (   exploit(_, File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Codigo, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl),
        format('-----------------------------------------------------~n'),
        safe_format('Código: ~w~n', Codigo),
        safe_format('Archivo: ~w~n', File),
        safe_format('Descripción: ~w~n', Description),
        safe_format('Fecha Publicación: ~w~n', DatePublished),
        safe_format('Autor: ~w~n', Author),
        safe_format('Tipo: ~w~n', Type),
        safe_format('Plataforma: ~w~n', Platform),
        safe_format('Puerto: ~w~n', Port),
        safe_format('Fecha Agregado: ~w~n', DateAdded),
        safe_format('Fecha Actualizado: ~w~n', DateUpdated),
        safe_format('Verificado: ~w~n', Verified),
        safe_format('Etiquetas: ~w~n', Tags),
        safe_format('Alias: ~w~n', Aliases),
        safe_format('Screenshot URL: ~w~n', ScreenshotUrl),
        safe_format('App URL: ~w~n', ApplicationUrl),
        safe_format('Fuente URL: ~w~n', SourceUrl),
        fail  % Continúa con el siguiente exploit en la base de datos
    ;   true % Termina cuando no haya más exploits
    ).

% Función para evitar mostrar campos no válidos o vacíos
safe_format(Formato, Valor) :-
    (   nonvar(Valor), Valor \= '' ->
        format(Formato, [Valor])
    ;   true
    ).

% Contar el número de vulnerabilidades en la base de datos
contar_vulnerabilidades(Cantidad) :-
    findall(Nombre, vulnerabilidad(Nombre, _, _, _, _, _, _), Vulnerabilidades),
    length(Vulnerabilidades, Cantidad).

% Contar el número de exploits en la base de datos
contar_exploits(Cantidad) :-
    findall(Codigo, exploit(_, _, _, _, _, _, _, _, _, _, _, _, Codigo, _, _, _, _), Exploits),
    length(Exploits, Cantidad).

% Mostrar el número de vulnerabilidades y exploits
mostrar_cantidad_datos :-
    contar_vulnerabilidades(CantVuln),
    contar_exploits(CantExploit),
    format('Hay ~w vulnerabilidades en la base de datos.~n', [CantVuln]),
    format('Hay ~w exploits en la base de datos.~n', [CantExploit]).

mostrar_codigos_exploits :-
    findall(Codigo, exploit(_, _, _, _, _, _, _, _, _, _, _, Codigo, _, _, _, _, _), Codigos),
    (   Codigos \= []
    ->  format('Códigos de Exploits: ~w~n', [Codigos])
    ;   writeln('No se encontraron códigos de exploits.')
    ).

% Mostrar todas las vulnerabilidades en la base de datos de manera legible
mostrar_vulnerabilidades :-
    format('--- Lista de Vulnerabilidades ---~n', []),
    vulnerabilidad(Nombre, Status, Description, References, Phase, Votes, Comments),
    mostrar_vulnerabilidad(Nombre, Status, Description, References, Phase, Votes, Comments),
    fail.  % Fuerza a Prolog a retroceder y encontrar más vulnerabilidades
mostrar_vulnerabilidades.  % Predicado vacío para finalizar el proceso sin errores
mostrar_vulnerabilidad(Nombre, Status, Description, References, Phase, Votes, Comments) :-
    format('-----------------------------------------------------~n', []),
    format('Nombre: ~w~nEstado: ~w~nDescripción: ~w~nReferencias: ~w~nFase: ~w~nVotos: ~w~nComentarios: ~w~n',
        [Nombre, Status, Description, References, Phase, Votes, Comments]).



% Mostrar una única vulnerabilidad en un formato más legible
mostrar_vulnerabilidad(Nombre, Status, Description, References, Phase, Votes, Comments) :-
    format('-----------------------------------------------------~n', []),
    format('Nombre: ~w~n', [Nombre]),
    format('Estado: ~w~n', [Status]),
    format('Descripción: ~w~n', [Description]),
    format('Referencias: ~w~n', [References]),
    format('Fase: ~w~n', [Phase]),
    format('Votos: ~w~n', [Votes]),
    format('Comentarios: ~w~n', [Comments]),
    format('-----------------------------------------------------~n', []).



consultar_exploits_por_codigo(Codigo) :-
    writeln(Codigo),  % Imprime el código para depuración
    findall(
        (File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl),
        exploit(_, File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Codigo, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl),
        Exploits
    ),
    (   Exploits \= []
    ->  format('--- Exploits para el código ~w ---~n', [Codigo]),
        forall(member((File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl), Exploits),
            format('Archivo: ~w~nDescripción: ~w~nFecha Publicación: ~w~nAutor: ~w~nTipo: ~w~nPlataforma: ~w~nPuerto: ~w~nFecha Agregado: ~w~nFecha Actualizado: ~w~nVerificado: ~w~nEtiquetas: ~w~nAlias: ~w~nScreenshot URL: ~w~nApp URL: ~w~nFuente URL: ~w~n',
            [File, Description, DatePublished, Author, Type, Platform, Port, DateAdded, DateUpdated, Verified, Tags, Aliases, ScreenshotUrl, ApplicationUrl, SourceUrl])
        )
    ;   format('No se encontró ningún exploit para el código ~w.~n', [Codigo])
    ).


mostrar_tipo_dato(V) :-
    (   atom(V) -> write('El tipo de dato es un átomo.')
    ;   string(V) -> write('El tipo de dato es una cadena.')
    ;   number(V) -> write('El tipo de dato es un número.')
    ;   write('El tipo de dato es desconocido.')
    ).

% Modificar la pregunta inicial para incluir la nueva opción
iniciar :-
    format('Bienvenido al sistema experto de seguridad. ¿En qué te gustaría obtener ayuda hoy?~n'),
    format('1. Información sobre una vulnerabilidad~n'),
    format('2. Información sobre un exploit~n'),
    format('3. Recomendaciones de ataque~n'),
    format('4. Mostrar todos los exploits~n'),
    format('5. Mostrar cantidad de vulnerabilidades y exploits~n'),
    format('6. Mostrar todas las vulnerabilidades~n'),  % Nueva opción agregada
    read(Opcion),
    ejecutar_opcion(Opcion).

% Ejecutar la opción seleccionada
ejecutar_opcion(1) :-
    prompt1('Introduce el nombre de la vulnerabilidad: '),  % Muestra el mensaje.
    get_single_char(_),  % Esto asegura que cualquier enter residual sea consumido.
    read_line_to_string(user_input, Nombre),  % Lee la entrada como string.
    writeln('Nombre ingresado:'), writeln(Nombre),  % Imprime lo que se ingresó.
    (Nombre \= "" -> consultar_vulnerabilidad_por_nombre(Nombre) ; format('No se ingresó ningún nombre.~n')),
    iniciar.  % Reinicia el menú.



ejecutar_opcion(2) :-
    format('Introduce el código del exploit: '),
    get_single_char(_),  % Esto asegura que cualquier enter residual sea consumido.
    read_line_to_string(user_input, Codigo),  
    atom_string(Atom, Codigo),
    consultar_exploits_por_codigo(Atom),
    
    iniciar.

ejecutar_opcion(3) :-
    format('Funcionalidad de recomendaciones de ataque aún no implementada.~n'),
    iniciar.
ejecutar_opcion(4) :-
    mostrar_exploits,
    iniciar.
ejecutar_opcion(5) :-
    mostrar_cantidad_datos,
    iniciar.
ejecutar_opcion(6) :-  % Opción para mostrar todas las vulnerabilidades
    mostrar_vulnerabilidades,
    iniciar.
ejecutar_opcion(_) :-
    format('Opción no válida, intenta de nuevo.~n'),
    iniciar.

:- cargar_vulnerabilidades('cve_db.csv').
:- cargar_exploits('exploit_db.csv').
:- iniciar.