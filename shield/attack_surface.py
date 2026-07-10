def analyze(result):
    exposure = []

    if result.get("scan_type") == "email":
        exposure.append("Adres e-mail może być używany do prób phishingu.")
        exposure.append("Nazwa użytkownika może być powiązana z innymi serwisami.")

    elif result.get("scan_type") == "username":
        exposure.append("Publiczne profile mogą ujawniać aktywność użytkownika.")
        exposure.append("Ta sama nazwa użytkownika może być używana w wielu serwisach.")

    elif result.get("scan_type") == "domain":
        exposure.append("Domena ujawnia publiczne rekordy DNS.")
        exposure.append("Serwer WWW może ujawniać informacje o konfiguracji.")

    elif result.get("scan_type") == "phone":
        exposure.append("Numer telefonu może być celem ataków SMS i vishingu.")

    elif result.get("scan_type") == "url":
        exposure.append("Adres URL może prowadzić do złośliwych stron lub wyłudzeń.")

    return exposure
