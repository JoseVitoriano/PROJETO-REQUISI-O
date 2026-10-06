import csv, io, json, os, re, secrets, sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "requisicoes.db")
STATUS = ["Aberta", "Pendente", "Em andamento", "Em cotação", "Aguard. aprovada",
          "Em standby", "Entregue parcialmente", "Concluída", "Cancelada"]

AREAS = ["Elétrica", "Fundações", "Alvenaria", "Hidráulica", "Acabamentos",
         "Terraplenagem", "CFTV e Alarmes", "Outros"]

STATUS_COR = {
    "Aberta": "#2563eb",                 # azul
    "Pendente": "#ea580c",               # laranja
    "Em andamento": "#0d9488",           # verde-água
    "Em cotação": "#7c3aed",             # roxo
    "Aguard. aprovada": "#db2777",       # rosa
    "Em standby": "#64748b",             # cinza-azulado
    "Entregue parcialmente": "#ca8a04",  # mostarda
    "Concluída": "#16a34a",              # verde
    "Cancelada": "#dc2626"}              # vermelho

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024)

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios(
  id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT UNIQUE NOT NULL, senha_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requisicoes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  numero_rav TEXT, area TEXT, observacoes TEXT,
  quantidade_requisitada REAL NOT NULL CHECK(quantidade_requisitada>=0),
  estoque_tdc REAL NOT NULL DEFAULT 0, estoque_ceramica REAL NOT NULL DEFAULT 0,
  estoque_construtora_sucesso REAL NOT NULL DEFAULT 0, comprado REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL, unidade_medida TEXT NOT NULL, descricao TEXT NOT NULL,
  envio TEXT, pedidos TEXT, numero_documento TEXT,
  valor REAL NOT NULL DEFAULT 0, preco_total REAL NOT NULL DEFAULT 0,
  situacao TEXT, data_cadastro TEXT NOT NULL, criado_por TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exclusoes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, requisicao_id INTEGER NOT NULL, numero_rav TEXT,
  descricao TEXT, dados TEXT NOT NULL, excluido_por TEXT NOT NULL, data_exclusao TEXT NOT NULL);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    with sqlite3.connect(DB) as c:
        c.executescript(SCHEMA)
        # migração: bancos criados antes do campo RAV
        if "numero_rav" not in [r[1] for r in c.execute("PRAGMA table_info(requisicoes)")]:
            c.execute("ALTER TABLE requisicoes ADD COLUMN numero_rav TEXT")
        cols = [r[1] for r in c.execute("PRAGMA table_info(requisicoes)")]
        if "area" not in cols:
            c.execute("ALTER TABLE requisicoes ADD COLUMN area TEXT")
        if "observacoes" not in cols:
            c.execute("ALTER TABLE requisicoes ADD COLUMN observacoes TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_requisicoes_rav ON requisicoes(numero_rav)")
        if not c.execute("SELECT 1 FROM usuarios").fetchone():
            pwd = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
            c.execute("INSERT INTO usuarios(usuario,senha_hash) VALUES('admin',?)",
                      (generate_password_hash(pwd),))
            print(f"\n>>> Usuário inicial: admin | Senha: {pwd} (troque/crie outros com 'flask criar-usuario')\n")

@app.cli.command("criar-usuario")
def criar_usuario():
    import click
    u = click.prompt("Usuário"); p = click.prompt("Senha (mín. 10)", hide_input=True)
    if len(p) < 10: raise click.ClickException("Senha curta.")
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO usuarios(usuario,senha_hash) VALUES(?,?)", (u, generate_password_hash(p)))
    click.echo("Criado.")

# ---------- segurança ----------
def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["cor_status"] = lambda s: STATUS_COR.get(s, "#475569")

@app.before_request
def csrf_protect():
    if request.method == "POST":
        t = request.form.get("_csrf", "")
        if not secrets.compare_digest(t, session.get("_csrf", "x")): abort(400)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    r.headers["Cache-Control"] = "no-store"
    return r

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user" not in session: return redirect(url_for("login"))
        return f(*a, **k)
    return w

TENT = {}  # tentativas de login por IP
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr; n, t = TENT.get(ip, (0, datetime.now()))
        if n >= 5 and datetime.now() - t < timedelta(minutes=10):
            flash("Muitas tentativas. Aguarde 10 minutos."); return render_template("login.html")
        u = db().execute("SELECT * FROM usuarios WHERE usuario=?", (request.form.get("usuario", ""),)).fetchone()
        if u and check_password_hash(u["senha_hash"], request.form.get("senha", "")):
            session.clear(); session.permanent = True; session["user"] = u["usuario"]
            TENT.pop(ip, None); return redirect(url_for("dashboard"))
        TENT[ip] = (n + 1, datetime.now()); flash("Usuário ou senha inválidos.")
    return render_template("login.html")

def limitado(chave):
    n, t = TENT.get(chave, (0, datetime.now()))
    return n >= 5 and datetime.now() - t < timedelta(minutes=10)

def falha(chave):
    n, t = TENT.get(chave, (0, datetime.now())); TENT[chave] = (n + 1, datetime.now())

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        ch = "cad" + str(request.remote_addr)
        if limitado(ch):
            flash("Muitas tentativas. Aguarde 10 minutos."); return render_template("cadastro.html")
        f = request.form; u = f.get("usuario", "").strip(); p = f.get("senha", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", u):
            flash("Usuário: 3 a 30 caracteres (letras, números, _ . -).")
        elif len(p) < 10 or p != f.get("confirmar", ""):
            flash("A senha deve ter ao menos 10 caracteres e ser igual à confirmação.")
        else:
            try:
                db().execute("INSERT INTO usuarios(usuario,senha_hash) VALUES(?,?)", (u, generate_password_hash(p)))
                db().commit(); falha(ch); flash("Login criado. Faça o acesso."); return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Esse usuário já existe.")
    return render_template("cadastro.html")

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

# ---------- validação ----------
def num(v, campo, obrig=True):
    v = (v or "").strip().replace(".", "").replace(",", ".") if "," in (v or "") else (v or "").strip()
    if not v and not obrig: return 0.0
    try: x = float(v)
    except ValueError: raise ValueError(f"{campo}: número inválido")
    if x < 0 or x > 1e12: raise ValueError(f"{campo}: valor fora do limite")
    return x

def txt(v, campo, mx, obrig=False):
    v = re.sub(r"\s+", " ", (v or "")).strip()
    if obrig and not v: raise ValueError(f"{campo}: obrigatório")
    if len(v) > mx: raise ValueError(f"{campo}: máx. {mx} caracteres")
    return v

RAV_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./_-]{0,29}")

def rav_valida(v):
    v = re.sub(r"\s+", "", v or "")
    if not RAV_RE.fullmatch(v): raise ValueError("Nº da RAV: use letras, números, . / _ - (máx. 30)")
    return v

def ler_form(f):
    d = dict(
        numero_rav=rav_valida(f.get("numero_rav")),
        quantidade_requisitada=num(f.get("quantidade_requisitada"), "Qtd. requisitada"),
        estoque_tdc=num(f.get("estoque_tdc"), "Estoque TDC", False),
        estoque_ceramica=num(f.get("estoque_ceramica"), "Estoque Cerâmica", False),
        estoque_construtora_sucesso=num(f.get("estoque_construtora_sucesso"), "Estoque Construtora Sucesso", False),
        comprado=num(f.get("comprado"), "Comprado", False),
        area=f.get("area"), observacoes=txt(f.get("observacoes"), "Observações", 500),
        status=f.get("status"), unidade_medida=txt(f.get("unidade_medida"), "Unidade", 20, True),
        descricao=txt(f.get("descricao"), "Descrição", 300, True),
        envio=txt(f.get("envio"), "Envio", 100), pedidos=txt(f.get("pedidos"), "Pedidos", 100),
        numero_documento=txt(f.get("numero_documento"), "Nº documento", 50),
        valor=num(f.get("valor"), "Valor", False), situacao=txt(f.get("situacao"), "Situação", 100))
    if d["status"] not in STATUS: raise ValueError("Status inválido")
    if d["area"] not in AREAS: raise ValueError("Área: selecione uma opção da lista")
    # observações só valem se o campo foi liberado (checkbox); caso contrário, fica vazio
    if not f.get("obs_ativa"): d["observacoes"] = ""
    d["preco_total"] = round(d["valor"] * d["quantidade_requisitada"], 2)  # valor unitário × qtd. requisitada
    return d

# ---------- telas ----------
@app.route("/")
@login_required
def dashboard():
    c = db()
    por_status = {s: 0 for s in STATUS}
    for r in c.execute("SELECT status, COUNT(*) n FROM requisicoes GROUP BY status"): por_status[r["status"]] = r["n"]
    k = c.execute("""SELECT COUNT(*) total, COALESCE(SUM(preco_total),0) valor,
        COALESCE(SUM(quantidade_requisitada),0) req, COALESCE(SUM(comprado),0) comp,
        COALESCE(SUM(estoque_tdc+estoque_ceramica+estoque_construtora_sucesso),0) est FROM requisicoes""").fetchone()
    # necessidade = requisitado - estoques - comprado (mínimo 0), por item
    nec = c.execute("""SELECT id, numero_rav, descricao, unidade_medida, status,
        MAX(quantidade_requisitada-estoque_tdc-estoque_ceramica-estoque_construtora_sucesso-comprado,0) AS necessidade
        FROM requisicoes WHERE status NOT IN ('Concluída','Cancelada') AND necessidade>0
        ORDER BY necessidade DESC LIMIT 10""").fetchall()
    return render_template("dashboard.html", por_status=por_status, k=k, nec=nec, mx=max(por_status.values()) or 1)

def filtro_rav():
    """Lê ?rav= e devolve (texto, cláusula SQL, parâmetros). Busca pelo nº da RAV (contém, sem diferenciar maiúsculas)."""
    q = request.args.get("rav", "").strip()
    if not q: return "", "", ()
    try: q = rav_valida(q)
    except ValueError:
        flash("Pesquise pelo número da RAV (letras, números, . / _ -)."); return "", "", ()
    esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return q, " WHERE numero_rav LIKE ? ESCAPE '\\'", (f"%{esc}%",)

@app.route("/requisicoes")
@login_required
def lista():
    q, where, par = filtro_rav()
    rows = db().execute("SELECT * FROM requisicoes" + where + " ORDER BY id DESC", par).fetchall()
    return render_template("lista.html", rows=rows, q=q)

@app.route("/nova", methods=["GET", "POST"])
@app.route("/editar/<int:rid>", methods=["GET", "POST"])
@login_required
def formulario(rid=None):
    atual = db().execute("SELECT * FROM requisicoes WHERE id=?", (rid,)).fetchone() if rid else None
    if rid and not atual: abort(404)
    if request.method == "POST":
        try:
            d = ler_form(request.form)
            if atual:
                cols = ",".join(f"{k}=?" for k in d)
                db().execute(f"UPDATE requisicoes SET {cols} WHERE id=?", (*d.values(), rid))
            else:
                d["data_cadastro"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); d["criado_por"] = session["user"]
                cur = db().execute(f"INSERT INTO requisicoes({','.join(d)}) VALUES({','.join('?'*len(d))})", tuple(d.values()))
                rid = cur.lastrowid
            db().commit(); flash(f"Requisição #{rid or atual['id']} salva."); return redirect(url_for("lista", rav=d["numero_rav"]))
        except ValueError as e:
            flash(str(e)); atual = request.form
    return render_template("form.html", r=atual, status=STATUS, areas=AREAS, rid=rid)

@app.post("/excluir/<int:rid>")
@login_required
def excluir(rid):
    c = db()
    r = c.execute("SELECT * FROM requisicoes WHERE id=?", (rid,)).fetchone()
    if not r: abort(404)
    try:
        # auditoria: guarda quem excluiu, quando e uma cópia completa do registro
        c.execute("INSERT INTO exclusoes(requisicao_id,numero_rav,descricao,dados,excluido_por,data_exclusao) VALUES(?,?,?,?,?,?)",
                  (rid, r["numero_rav"], r["descricao"], json.dumps(dict(r), ensure_ascii=False),
                   session["user"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        c.execute("DELETE FROM requisicoes WHERE id=?", (rid,))
        c.commit()
    except sqlite3.Error:
        c.rollback(); flash("Não foi possível excluir a requisição."); return redirect(url_for("lista"))
    flash(f"Requisição #{rid} excluída.")
    return redirect(url_for("lista", rav=r["numero_rav"] or ""))

@app.route("/relatorio.csv")
@login_required
def relatorio():
    q, where, par = filtro_rav()
    rows = db().execute("SELECT * FROM requisicoes" + where + " ORDER BY id", par).fetchall()
    out = io.StringIO(); w = csv.writer(out, delimiter=";")
    cols = rows[0].keys() if rows else ["id"]
    w.writerow(cols)
    for r in rows:  # neutraliza injeção de fórmula no Excel
        w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in tuple(r)])
    nome = f"RAV_{re.sub(r'[^A-Za-z0-9_-]', '_', q)}.csv" if q else "requisicoes.csv"
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nome}"})

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # em produção: gunicorn/waitress + HTTPS
