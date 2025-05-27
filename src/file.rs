use std::fs::{create_dir_all, read, read_dir, File};
use std::io;
use std::io::{prelude::*, Error, ErrorKind};
use std::path::{Path, PathBuf};

pub fn write_in<P: AsRef<Path>>(filename: P, content: &[u8]) -> std::io::Result<()> {
    let path = filename.as_ref();

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("Le dossier '{}' n'existe pas", parent.display()),
            ));
        }
    }

    let mut file = File::create(path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn force_write_in<P: AsRef<Path>>(filename: P, content: &[u8]) -> std::io::Result<()> {
    let path = filename.as_ref();

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(path)?;
    file.write_all(content)?;
    Ok(())
}

pub fn read_file<P: AsRef<Path>>(filename: P) -> std::io::Result<Vec<u8>> {
    let path = filename.as_ref();

    if !path.exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("Le fichier '{}' n'existe pas", path.display()),
        ));
    }

    read(path)
}

pub fn find_files_by_extensions_recursive<P: AsRef<Path>>(
    directory: P,
    extensions: &[&str],
) -> io::Result<Vec<PathBuf>> {
    find_files_by_extensions_recursive_with_exclusions(directory, extensions, &[])
}

pub fn find_files_by_extensions_recursive_with_exclusions<P: AsRef<Path>>(
    directory: P,
    extensions: &[&str],
    excluded_dirs: &[&str],
) -> io::Result<Vec<PathBuf>> {
    let path = directory.as_ref();

    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Le dossier '{}' n'existe pas", path.display()),
        ));
    }

    let mut matching_files = Vec::new();

    // Normaliser les extensions
    let normalized_extensions: Vec<String> = extensions
        .iter()
        .map(|ext| {
            let ext = ext.trim();
            if ext.starts_with('.') {
                ext.to_lowercase()
            } else {
                format!(".{}", ext.to_lowercase())
            }
        })
        .collect();

    // Normaliser les dossiers exclus (en minuscules pour comparaison insensible à la casse)
    let normalized_excluded_dirs: Vec<String> =
        excluded_dirs.iter().map(|dir| dir.to_lowercase()).collect();

    // Ignorer les erreurs de permission et continuer
    let _ = find_files_recursive_with_exclusions(
        path,
        &normalized_extensions,
        &normalized_excluded_dirs,
        &mut matching_files,
    );

    Ok(matching_files)
}

fn find_files_recursive_with_exclusions(
    dir: &Path,
    extensions: &[String],
    excluded_dirs: &[String],
    results: &mut Vec<PathBuf>,
) -> io::Result<()> {
    // Vérifier si le dossier actuel doit être exclu
    let current_dir_str = dir.to_string_lossy().to_lowercase();
    for excluded in excluded_dirs {
        if current_dir_str.starts_with(excluded) {
            return Ok(()); // Ignorer ce dossier et tous ses sous-dossiers
        }
    }

    // Tenter de lire le dossier, ignorer les erreurs de permission
    let entries = match read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            // Ignorer silencieusement les erreurs de permission
            if e.kind() == io::ErrorKind::PermissionDenied {
                return Ok(());
            }
            // Pour les autres erreurs, on peut choisir de les ignorer aussi ou les propager
            return Ok(()); // Ignorer toutes les erreurs pour être plus robuste
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue, // Ignorer les entrées qui causent des erreurs
        };

        let path = entry.path();

        if path.is_dir() {
            // Parcourir récursivement les sous-dossiers (ignorer les erreurs)
            let _ = find_files_recursive_with_exclusions(&path, extensions, excluded_dirs, results);
        } else if path.is_file() {
            // Vérifier l'extension du fichier
            if let Some(file_extension) = path.extension() {
                if let Some(ext_str) = file_extension.to_str() {
                    let file_ext = format!(".{}", ext_str.to_lowercase());

                    if extensions.contains(&file_ext) {
                        results.push(path);
                    }
                }
            }
        }
    }
    Ok(())
}

fn find_files_recursive(
    dir: &Path,
    extensions: &[String],
    results: &mut Vec<PathBuf>,
) -> io::Result<()> {
    find_files_recursive_with_exclusions(dir, extensions, &[], results)
}
