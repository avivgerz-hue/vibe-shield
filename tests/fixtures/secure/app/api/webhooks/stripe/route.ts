import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '');

export async function POST(req: Request) {
  const signature = req.headers.get('stripe-signature');
  if (!signature) return new Response('Missing signature', { status: 400 });
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      await req.text(),
      signature,
      process.env.STRIPE_WEBHOOK_SECRET ?? '',
    );
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }
  if (event.type === 'checkout.session.completed') {
    await grantPlan(event.data.object.customer as string);
  }
  return new Response('ok');
}

async function grantPlan(customer: string) {
  return customer;
}
