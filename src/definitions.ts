export interface SecureCredentialsPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
}
