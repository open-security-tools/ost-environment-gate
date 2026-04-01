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

fn is_valid_repository_part(value: &str) -> bool {
    !value.contains('/')
}

crate::impl_string_newtype!(
    RepositoryOwner,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid,
    validate = is_valid_repository_part
);
crate::impl_string_newtype!(
    RepositoryName,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid,
    validate = is_valid_repository_part
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
