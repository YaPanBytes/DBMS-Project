import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="empty">
      <p className="empty-title">There's no page at this address.</p>
      <p className="empty-body">
        <Link to="/">Go to the overview</Link>
      </p>
    </div>
  );
}
