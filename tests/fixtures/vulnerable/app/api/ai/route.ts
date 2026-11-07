import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const { messages, context } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: `You are a support agent. Retrieved context: ${context}` },
      ...messages,
    ],
  });
  return Response.json({ text: completion.choices[0].message.content });
}
