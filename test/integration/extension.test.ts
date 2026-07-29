import * as assert from 'node:assert';
import * as vscode from 'vscode';

// Derive the id from the manifest so a publisher change can't break the
// suite silently.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const manifest = require('../../package.json') as {
	name: string;
	publisher: string;
};
const EXTENSION_ID = `${manifest.publisher}.${manifest.name}`;

describe('Secrets-LE integration', function () {
	this.timeout(30_000);

	it('activates', async () => {
		const extension = vscode.extensions.getExtension(EXTENSION_ID);
		assert.ok(extension, `extension ${EXTENSION_ID} not found`);
		await extension.activate();
		assert.strictEqual(extension.isActive, true);
	});

	it('registers every declared command', async () => {
		const extension = vscode.extensions.getExtension(EXTENSION_ID);
		await extension?.activate();
		const commands = await vscode.commands.getCommands(true);
		for (const id of [
			'secrets-le.detect',
			'secrets-le.sanitize',
			'secrets-le.openSettings',
			'secrets-le.help',
		]) {
			assert.ok(commands.includes(id), `missing command: ${id}`);
		}
	});

	it('detect scans the workspace and opens a results document', async () => {
		const extension = vscode.extensions.getExtension(EXTENSION_ID);
		await extension?.activate();

		await vscode.commands.executeCommand('secrets-le.detect');

		const resultDoc = vscode.workspace.textDocuments.find(
			(doc) =>
				doc.languageId === 'markdown' &&
				doc.getText().includes('# Secrets Detection Results'),
		);
		assert.ok(resultDoc, 'no results document found');
		const text = resultDoc.getText();
		// The fixture workspace .env carries an api key and a password.
		assert.ok(text.includes('.env'), 'results not grouped by file');
		assert.ok(/API-KEY|PASSWORD/.test(text), 'expected secret types missing');
	});

	it('help opens an in-editor markdown document', async () => {
		await vscode.commands.executeCommand('secrets-le.help');
		const helpDoc = vscode.workspace.textDocuments.find((doc) =>
			doc.getText().startsWith('# Secrets-LE Help'),
		);
		assert.ok(helpDoc, 'no help document found');
	});
});
