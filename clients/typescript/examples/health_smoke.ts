/** W40-05: TypeScript client smoke example. */
const addr = process.env.KNXVAULT_ADDR ?? 'http://127.0.0.1:8200';

async function main(): Promise<void> {
  const res = await fetch(`${addr}/health`);
  console.log(await res.text());
}

main().catch(console.error);