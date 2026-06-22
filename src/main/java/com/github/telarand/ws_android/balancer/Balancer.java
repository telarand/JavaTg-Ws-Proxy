package com.github.telarand.ws_android.balancer;

import java.util.*;

/**
 * Балансировщик, управляющий списком доменов и маппингом DC → домен.
 * Полностью соответствует Python-классу _Balancer.
 */
public final class Balancer {

    public static final Balancer INSTANCE = new Balancer();

    private Balancer() {
    }

    private final List<String> domains = new ArrayList<>();
    private final Map<Integer, String> dcToDomain = new HashMap<>();

    /**
     * Сравнивает два списка как мультимножества (по частоте элементов).
     */
    private static <T> boolean areMultisetsEqual(List<T> list1, List<T> list2) {
        if (list1.size() != list2.size()) return false;
        Map<T, Integer> freq1 = new HashMap<>();
        Map<T, Integer> freq2 = new HashMap<>();
        for (T item : list1) freq1.put(item, freq1.getOrDefault(item, 0) + 1);
        for (T item : list2) freq2.put(item, freq2.getOrDefault(item, 0) + 1);
        return freq1.equals(freq2);
    }

    /**
     * Обновляет список доменов, если он изменился (по мультимножеству).
     * Также пересоздаёт случайный маппинг для всех DC.
     */
    public synchronized void updateDomainsList(List<String> domainsList) {
        if (areMultisetsEqual(this.domains, domainsList)) {
            return;
        }

        this.domains.clear();
        this.domains.addAll(domainsList);

        int[] dcIds = {1, 2, 3, 4, 5, 203};
        Random random = new Random();
        for (int dcId : dcIds) {
            if (!this.domains.isEmpty()) {
                String chosen = this.domains.get(random.nextInt(this.domains.size()));
                this.dcToDomain.put(dcId, chosen);
            } else {
                this.dcToDomain.put(dcId, null);
            }
        }
    }

    /**
     * Обновляет домен для конкретного DC.
     * @return true, если домен был изменён, иначе false.
     */
    public synchronized boolean updateDomainForDc(int dcId, String domain) {
        String current = this.dcToDomain.get(dcId);
        if (Objects.equals(current, domain)) {
            return false;
        }
        this.dcToDomain.put(dcId, domain);
        return true;
    }

    /**
     * Возвращает итератор по доменам для указанного DC:
     * сначала закреплённый домен (если есть), затем все остальные домены
     * из общего списка в случайном порядке (кроме закреплённого).
     */
    public synchronized Iterator<String> getDomainsForDc(int dcId) {
        String currentDomain = this.dcToDomain.get(dcId);

        List<String> result = new ArrayList<>();

        if (currentDomain != null) {
            result.add(currentDomain);
        }

        List<String> shuffled = new ArrayList<>(this.domains);
        Collections.shuffle(shuffled, new Random());

        for (String domain : shuffled) {
            if (!Objects.equals(domain, currentDomain)) {
                result.add(domain);
            }
        }

        return result.iterator();
    }

    public synchronized Map<Integer, String> getDcToDomain() {
        return new HashMap<>(this.dcToDomain);
    }

    public synchronized List<String> getDomains() {
        return new ArrayList<>(this.domains);
    }
}