
import { renderCredentialForm } from './build/auth/credential-form.js';

const schema = {
  server: "test-server",
  displayName: "Test Server",
  description: "This is a descriptive test for the credential form a11y improvement.",
  fields: []
};

const html = renderCredentialForm(schema, { submitUrl: "http://localhost/submit" });
console.log(html);
