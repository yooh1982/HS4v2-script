#!/usr/bin/env python3
"""Git 저장소 초기화 및 설정 스크립트"""

import os
import subprocess
import shutil
from pathlib import Path

def run_command(cmd, cwd=None):
    """명령 실행"""
    print(f"실행: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode == 0

def main():
    base_dir = Path("/Users/yoohyoung/Library/CloudStorage/OneDrive-UANGELCorporation/workspace/Cursor/HS4v2-scripts")
    os.chdir(base_dir)
    
    print("=" * 60)
    print("Git 저장소 초기화 시작")
    print("=" * 60)
    
    # 1. 기존 .git 디렉토리 삭제
    git_dir = base_dir / ".git"
    if git_dir.exists():
        print(f"\n1. 기존 .git 디렉토리 삭제 중...")
        shutil.rmtree(git_dir)
        print("   ✓ 삭제 완료")
    else:
        print(f"\n1. .git 디렉토리가 없습니다.")
    
    # 2. reverse-proxy/.git 디렉토리도 확인
    reverse_proxy_git = base_dir / "reverse-proxy" / ".git"
    if reverse_proxy_git.exists():
        print(f"\n2. reverse-proxy/.git 디렉토리 삭제 중...")
        shutil.rmtree(reverse_proxy_git)
        print("   ✓ 삭제 완료")
    else:
        print(f"\n2. reverse-proxy/.git 디렉토리가 없습니다.")
    
    # 3. git init
    print(f"\n3. git init 실행 중...")
    if run_command("git init", cwd=base_dir):
        print("   ✓ git init 완료")
    else:
        print("   ✗ git init 실패")
        return
    
    # 4. git add
    print(f"\n4. git add . 실행 중...")
    if run_command("git add .", cwd=base_dir):
        print("   ✓ git add 완료")
    else:
        print("   ✗ git add 실패")
        return
    
    # 5. git status 확인
    print(f"\n5. git status 확인 중...")
    run_command("git status", cwd=base_dir)
    
    # 6. git commit
    print(f"\n6. git commit 실행 중...")
    if run_command('git commit -m "Initial commit: Add reverse-proxy"', cwd=base_dir):
        print("   ✓ git commit 완료")
    else:
        print("   ✗ git commit 실패")
        return
    
    # 7. 브랜치를 main으로 설정
    print(f"\n7. 브랜치를 main으로 설정 중...")
    run_command("git branch -M main", cwd=base_dir)
    
    # 8. 원격 저장소 추가
    print(f"\n8. 원격 저장소 추가 중...")
    run_command("git remote remove origin", cwd=base_dir)  # 기존이 있으면 제거
    if run_command("git remote add origin https://github.com/yooh1982/HS4v2-script.git", cwd=base_dir):
        print("   ✓ 원격 저장소 추가 완료")
    else:
        print("   ✗ 원격 저장소 추가 실패 (이미 존재할 수 있음)")
    
    # 9. 원격 저장소 확인
    print(f"\n9. 원격 저장소 확인 중...")
    run_command("git remote -v", cwd=base_dir)
    
    # 10. push
    print(f"\n10. git push 실행 중...")
    print("   (인증이 필요할 수 있습니다)")
    run_command("git push -u origin main", cwd=base_dir)
    
    print("\n" + "=" * 60)
    print("완료!")
    print("=" * 60)

if __name__ == "__main__":
    main()

