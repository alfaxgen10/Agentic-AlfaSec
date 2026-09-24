@echo off
cd /d "%~dp0"
if not exist AgenticAlfaSecAgent.class javac AgenticAlfaSecAgent.java
java AgenticAlfaSecAgent
