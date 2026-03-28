"""Known safe values and false positive filters."""

# Emails seguros (placeholders / testes)
SAFE_EMAILS = {
    "example@example.com", "user@example.com", "test@test.com",
    "noreply@example.com", "user@domain.com", "email@example.com",
    "admin@example.com", "info@example.com", "foo@bar.com",
    "usuario@email.com", "contato@exemplo.com.br"
}

SAFE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com",
    "localhost", "placeholder.com", "domain.com", "email.com"
}

SAFE_EMAIL_PREFIXES = {"noreply", "no-reply", "donotreply", "do-not-reply"}

# CPFs inválidos conhecidos
SAFE_CPF_PATTERNS = {
    "00000000000", "11111111111", "22222222222", "33333333333",
    "44444444444", "55555555555", "66666666666", "77777777777",
    "88888888888", "99999999999", "12345678909"
}

# Telefones claramente falsos
SAFE_PHONES = {"0000000000", "00000000000", "1111111111", "11111111111"}

# Cartões de teste oficiais (Luhn válido mas reconhecidamente fictícios)
KNOWN_TEST_CARDS = {
    "4111111111111111",   # Visa test (Stripe)
    "5500000000000004",   # Mastercard test
    "378282246310005",    # Amex test
    "6011111111111117",   # Discover test
    "3530111333300000",   # JCB test
    "4012888888881881",   # Visa test 2
    "5200828282828210",   # Mastercard test 2
}

# Nomes próprios brasileiros (300+ mais comuns IBGE)
BR_NAMES_COMMON = {
    # Femininos
    "maria", "ana", "francisca", "antonia", "adriana", "juliana", "marcia",
    "fernanda", "patricia", "aline", "sandra", "camila", "amanda", "brenda",
    "jessica", "leticia", "larissa", "rafaela", "gabriela", "carolina",
    "beatriz", "vanessa", "simone", "renata", "priscila", "paula", "natalia",
    "monica", "lucia", "luciana", "liliane", "katia", "kelly", "jaqueline",
    "isabela", "helena", "flavia", "elaine", "denise", "debora", "cristiane",
    "claudia", "carla", "bianca", "barbara", "andreia", "alessandra",
    "viviane", "tatiana", "sueli", "rosa", "raquel", "mariana", "lidia",
    "lilian", "lena", "laura", "keila", "joyce", "josiane", "joana",
    "irene", "iracema", "inês", "ines", "gisele", "glaucia", "graciela",
    "edilene", "edna", "elisa", "elizabete", "elizabeth", "emanuelle",
    "fabiana", "fatima", "izabel", "izadora", "jenifer", "joelma",
    "katiane", "karina", "leila", "luana", "luisa", "luiza",
    "marta", "miriam", "neuza", "noemia", "paloma", "regiane",
    "rita", "rosana", "rosangela", "roselia", "rosilene", "rosimeire",
    "sabrina", "samara", "sara", "sheila", "silvia", "silvana",
    "solange", "sonia", "soraya", "stela", "suzana", "talita",
    "tamires", "tanara", "tania", "telma", "tereza", "thais",
    "valdirene", "valeria", "vera", "veronica", "vilma", "vitoria",
    "wanessa", "wellington", "yasmin", "yara",
    # Masculinos
    "jose", "joao", "antonio", "francisco", "carlos", "paulo", "pedro",
    "lucas", "luiz", "marcos", "luis", "gabriel", "rafael", "daniel",
    "marcelo", "rodrigo", "manoel", "manuel", "ernesto", "sergio",
    "jorge", "arthur", "augusto", "andre", "alex", "alan", "adao",
    "abel", "abraao", "adalberto", "adalto", "adauto",
    "adriano", "agostinho", "ailton", "airton", "aldo", "aldomar",
    "alef", "aleixo", "aleson", "alexandre", "alexsandro", "alfredo",
    "alisson", "almir", "alonso", "altair", "altamiro", "altivo",
    "alvin", "americo", "amilcar", "amir", "anderson", "elton",
    "evandro", "everton", "fabiano", "fabio", "feliciano", "felipe",
    "fernando", "filipe", "flavio", "frederico", "geovane", "geraldo",
    "gilberto", "gilmar", "gladson", "glauber", "glauco", "gleison",
    "guilherme", "gustavo", "henrique", "hugo", "igor",
    "ilton", "irineu", "ivan", "ivanildo", "ivo", "jacinto",
    "jaime", "jair", "janio", "jeferson", "jefferson", "jhonatan",
    "joaquim", "jonathan", "jonas", "jonatas", "jordan", "josemar",
    "josimar", "josue", "junior", "kleber", "laercio", "lairton",
    "lauro", "leandro", "leidson", "leoncio", "leonel",
    "licio", "lindomar", "lineu", "lucio", "luisinho", "maicon",
    "marcio", "mario", "mateus", "matheus", "mauricio", "mauro",
    "maxwell", "michel", "miguel", "murilo", "nelson", "nilton",
    "noel", "odilon", "olimpio", "orion", "osmar", "osorio",
    "paul", "reginaldo", "reinaldo", "renan", "renato", "reno",
    "ricardo", "rinaldo", "robson", "rogerio", "romario", "romulo",
    "ronaldo", "roni", "ronivon", "rubens", "rudmar", "rui",
    "samuel", "saulo", "sebastiao", "sidnei", "sidney", "silvano",
    "silvestre", "sirio", "tadeu", "tiago", "tito", "toni", "tony",
    "valdo", "valdir", "vinicius", "vitor", "wagner", "wander",
    "wanderlei", "washington", "welton", "wendel", "wilian", "willian",
    "wilson", "wladimir", "yago", "yuri", "zacarias", "zenon",
}


def email_is_safe(email: str) -> bool:
    email = email.lower().strip()
    if email in SAFE_EMAILS:
        return True
    domain = email.split("@")[-1] if "@" in email else ""
    prefix = email.split("@")[0] if "@" in email else ""
    if domain in SAFE_EMAIL_DOMAINS:
        return True
    if any(prefix.startswith(p) for p in SAFE_EMAIL_PREFIXES):
        return True
    return False
