use crate::error::AppError;

id_type!(RepositoryId);

/// Stores a validated GitHub repository owner name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RepositoryOwner(String);

/// Stores a validated GitHub repository name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RepositoryName(String);

/// Identifies a GitHub repository by its owner and name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(into = "String")]
pub struct Repository {
    owner: RepositoryOwner,
    name: RepositoryName,
}

/// Returns `true` when every character in `value` is safe for use in a URL path
/// segment. This matches the character sets GitHub allows for owner and repository
/// names (alphanumeric, hyphen, underscore, period) and prevents URL-injection
/// characters like `..`, `#`, `?`, `%`, or `@` from reaching `Url::join`.
fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && value != "."
        && value != ".."
}

crate::impl_string_newtype!(
    RepositoryOwner,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid,
    validate = is_valid_slug
);
crate::impl_string_newtype!(
    RepositoryName,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid,
    validate = is_valid_slug
);

impl Repository {
    /// Returns the validated repository owner.
    pub fn owner(&self) -> &RepositoryOwner {
        &self.owner
    }

    /// Returns the validated repository name.
    pub fn name(&self) -> &RepositoryName {
        &self.name
    }
}

impl std::fmt::Display for Repository {
    /// Formats the repository as `owner/name`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

impl From<Repository> for String {
    fn from(value: Repository) -> Self {
        value.to_string()
    }
}

impl TryFrom<(String, String)> for Repository {
    type Error = AppError;

    /// Builds a repository from separately validated owner and name strings.
    fn try_from((owner, name): (String, String)) -> Result<Self, Self::Error> {
        Ok(Self {
            owner: owner.try_into()?,
            name: name.try_into()?,
        })
    }
}

impl TryFrom<String> for Repository {
    type Error = AppError;

    /// Parses a repository from its `owner/name` string representation.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split('/');
        let owner = parts.next().unwrap_or_default();
        let name = parts.next().unwrap_or_default();
        if owner.is_empty() || name.is_empty() || parts.next().is_some() {
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }

        Self::try_from((owner.to_owned(), name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::{is_valid_slug, Repository, RepositoryName, RepositoryOwner};

    #[test]
    fn is_valid_slug_accepts_typical_github_names() {
        assert!(is_valid_slug("octocat"));
        assert!(is_valid_slug("my-org"));
        assert!(is_valid_slug("repo_name"));
        assert!(is_valid_slug("my.repo"));
        assert!(is_valid_slug("A-Z_0.9"));
    }

    #[test]
    fn is_valid_slug_rejects_path_traversal_and_url_injection() {
        assert!(!is_valid_slug(".."));
        assert!(!is_valid_slug("."));
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug("foo/bar"));
        assert!(!is_valid_slug("foo#bar"));
        assert!(!is_valid_slug("foo?bar"));
        assert!(!is_valid_slug("foo%20bar"));
        assert!(!is_valid_slug("foo@bar"));
        assert!(!is_valid_slug("foo bar"));
    }

    #[test]
    fn repository_owner_rejects_unsafe_characters() {
        assert!(RepositoryOwner::try_from(String::from("..")).is_err());
        assert!(RepositoryOwner::try_from(String::from("foo#bar")).is_err());
        assert!(RepositoryOwner::try_from(String::from("foo?x=1")).is_err());
        assert!(RepositoryOwner::try_from(String::from("valid-owner")).is_ok());
    }

    #[test]
    fn repository_name_rejects_unsafe_characters() {
        assert!(RepositoryName::try_from(String::from("..")).is_err());
        assert!(RepositoryName::try_from(String::from("repo#frag")).is_err());
        assert!(RepositoryName::try_from(String::from("valid.repo-name_1")).is_ok());
    }

    #[test]
    fn repository_from_full_name_rejects_unsafe_components() {
        assert!(Repository::try_from(String::from("../evil")).is_err());
        assert!(Repository::try_from(String::from("owner/..")).is_err());
        assert!(Repository::try_from(String::from("ok-owner/ok-repo")).is_ok());
    }
}
