export default function NotesCard({
  title,
  notes,
}: {
  title: string;
  notes: string;
}) {
  return (
    <section className="block">
      <h2 className="block-title">{title}</h2>
      <div className="note-body">{notes}</div>
    </section>
  );
}
