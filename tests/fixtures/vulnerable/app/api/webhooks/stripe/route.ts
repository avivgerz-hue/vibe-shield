export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') {
    await grantPlan(event.data.object.customer);
  }
  return new Response('ok');
}

async function grantPlan(customer: string) {
  return customer;
}
