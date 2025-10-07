export default function Header({ title = "Embedded Secrets" }) {
    return (
        <header className = "app-header">
            <div className = "container">
                <h1 className = "app-title">{title}</h1>
            </div>
        </header>
);
}