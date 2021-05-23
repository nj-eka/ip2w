"""tasks.py
Simple tutorial invoke based task execution tool for building debian package (rpm support in process...) of ip2w application.
Use [invoke.yaml] config file or cli params (see @task specification)

Usage:
    invoke builddeb --no-use-git | --use-git (default)
"""

import os
import time
import tempfile as tmp
from pathlib import Path
from shutil import copyfile
from invoke import task, context, Collection, Config
from git import Repo  # https://gitpython.readthedocs.io/en/stable/

def git_update_ctx(source: Path, ctx: context.Context):
    "Update ctx from git"
    repo = Repo(source)
    head_commit = repo.head.commit
    # repo_config = repo.config_reader()
    ctx.update({
        "project": {
            "url": repo.remotes.origin.url, # git remote get-url origin
            "name": repo.remotes.origin.url.rstrip('.git').rpartition("/")[-1],  # git remote get-url origin | xargs basename -s .git
            "version": str(head_commit),  # GIT_VERSION="$(git rev-list HEAD -n 1)"
            "branch": head_commit.name_rev.split(" ")[-1],  #  BRANCH="$(git name-rev --name-only HEAD)"
            "updated_date": head_commit.committed_date,
            "author": head_commit.author.name,  # $(git config user.name) <$(git config user.email)>
            "author_email": head_commit.author.email,
        }
    })

def path_resolve(path, default_path) -> Path:
    "Resolve path. if [path] is None or empty then [default_path]."
    return Path(path or  default_path).expanduser().resolve()

def get_existing_dir(directory: Path) -> Path:
    "Return existing directory, create if it doesn't exist (full path with parents)."
    if not directory.exists():
        directory.mkdir(parents = True, exist_ok=True)
    return directory

@task(help={
            "source": "Source directory",
            "config": "Config directory",
            "debian": "DEBIAN directory",
            "output": "Output .deb directory",
            "use_git": "Use git to get project info",
    }, optional=['use_git'])
def build_deb(ctx, source = None, config = None, debian = None, output = None, use_git = None):
    "Build .deb package."
    source_path = ctx.config.deb.source = path_resolve(source, ctx.config.deb.source)
    config_path = ctx.config.deb.config = path_resolve(config, ctx.config.deb.config)
    debian_path = ctx.config.deb.debian = path_resolve(debian, ctx.config.deb.debian)
    output_path = ctx.config.deb.output = path_resolve(output, ctx.config.deb.output)
    use_git = use_git or bool(ctx.config.deb.get('use_git', 'false'))
    if use_git:
        git_update_ctx(source_path, ctx)
    # todo: add templates support
    with tmp.TemporaryDirectory() as tmp_dir:
        build_root_dir = Path(tmp_dir)  # / ctx.config.project.name    
        with ctx.cd(build_root_dir):
            build_project_dir = get_existing_dir(build_root_dir / ctx.config.project.name)
            ctx.run(f'cp -r "{debian_path}" "{build_project_dir}"')
            with open(debian_path / 'conffiles') as c_f:
                conffiles = c_f.read()
                files_to = dict((os.path.basename(file), build_project_dir.joinpath(file.lstrip("/"))) for file in conffiles.split())
            files_from = dict((file.name, file) for src in [source_path, config_path] for file in src.iterdir() if file.is_file())
            for file_name in files_from.keys() & files_to.keys():
                files_to[file_name].parent.mkdir(parents=True, exist_ok=True)
                copyfile(files_from[file_name], files_to[file_name])
            deb_file = output_path / f'{ctx.config.project.name}-{ctx.config.project.version}.deb'
            ctx.run(f"fakeroot dpkg -b ./{ctx.config.project.name} {deb_file}")
            ctx.run("tree")

class SafeDict(dict):
    "SafeDict to use in str.format_map"
    def __missing__(self, key):
        return '{' + key + '}'

def process_run_ctx(ctx, run_ctx):
    """ Process run context as following:
    working_dir: <working directory>
    params:
        param-name: <param-value>
        ...
    run: [cmd list]   
    """
    working_dir = run_ctx.get("working_dir", os.getcwd())
    with ctx.cd(working_dir):
        ctx.run("pwd")
        for run_cmd in run_ctx.get("run", []):
            print(run_cmd.format_map(SafeDict(**run_ctx.get("params",{}))))
            ctx.run(run_cmd.format_map(SafeDict(**run_ctx.get("params",{}))), echo=True, warn=True)

@task()
def build_rpm(ctx):
    "Run ctx = ctx.rpm"
    process_run_ctx(ctx, ctx.rpm)

@task()
def docker_build(ctx, target):
    "Run ctx = ctx.docker.build[target]"
    process_run_ctx(ctx, ctx.docker.build[target])

@task()
def docker_run(ctx, target):
    "Run ctx = ctx.docker.run[target]"
    process_run_ctx(ctx, ctx.docker.run[target])

@task()
def run_tests(ctx, target):
    "Run ctx = ctx.tests[target]"
    process_run_ctx(ctx, ctx.tests[target])

tasks_dir = os.path.dirname(__file__)
ns = Collection(build_deb, build_rpm, docker_build, docker_run, run_tests)
default_config = Config(defaults={
    "run": {"pty": True},
    "deb": {
        'use_git': False,
        'source': tasks_dir,
        'config': os.path.join(tasks_dir, "builddeb", "config"),
        'debian': os.path.join(tasks_dir, "builddeb", "DEBIAN"),
        'output': os.path.join(tasks_dir, "builddeb")
    },
    "project": {
        'name': "<project-name>",
        'version': "<project-version",
        'branch': "<project-branch>",
        'updated_date': int(time.time()),
        'author': "<project-author>",
        'author_email': "<project-author>-email",
    },
})
ns.configure(default_config)
