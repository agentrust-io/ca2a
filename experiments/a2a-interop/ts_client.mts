// Actual official TypeScript SDK request, with an ephemeral Python-made proof.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
const sdk = process.argv[2];
const { ClientFactory } = await import(pathToFileURL(resolve(sdk, 'src/client/index.ts')).href);
const { SendMessageRequest, Message } = await import(pathToFileURL(resolve(sdk, 'src/types/protojson.ts')).href);
let data = '';
for await (const chunk of process.stdin) data += chunk;
const input = JSON.parse(data);
const client = await new ClientFactory().createFromUrl(input.url);
const request = SendMessageRequest.fromJSON({message: input.message});
const result = await client.sendMessage(request, {
  serviceParameters: input.optIn ? {'A2A-Extensions': input.extension} : {},
  signal: AbortSignal.timeout(10000),
});
process.stdout.write(JSON.stringify(Message.toJSON(result)));
