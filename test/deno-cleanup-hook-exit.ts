import { open } from 'npm:lmdb';

try {
	Deno.removeSync('test/testdata-cleanup-hook', { recursive: true });
} catch (error) {
	if (error.name != 'NotFound') throw error;
}

// This child process intentionally mixes:
// - one env that is explicitly closed before process exit
// - one env left open until Deno tears the environment down
// - one delete-on-close env created through open()
//
// That combination exercises both new cleanup-hook fixes:
// - the per-EnvWrap cleanup(this) registration/removal balance
// - the openEnvWraps bookkeeping hook that now registers with a unique arg
const explicitlyClosed = open('test/testdata-cleanup-hook/explicit', {
	name: 'explicit-close',
	useVersions: true,
	overlappingSync: true,
});
const exitClosed = open('test/testdata-cleanup-hook/exit', {
	name: 'exit-close',
	useVersions: true,
	overlappingSync: true,
});
const deleteOnClose = open();

await explicitlyClosed.put('key', 'value');
await exitClosed.put('key', 'value');
await deleteOnClose.put('key', 'value');

// This explicit close used to be one of the teardown paths that could race
// against env cleanup and trigger "remove cleanup hook which was not registered".
await explicitlyClosed.close();
