import org.springframework.web.bind.annotation.*;

@RestController
class CheckoutController {
    private final OrderRepository orders;
    private final PaymentGateway gateway;
    CheckoutController(OrderRepository orders, PaymentGateway gateway) {
        this.orders = orders;
        this.gateway = gateway;
    }
    @PostMapping("/orders/{orderId}/pay")
    Order pay(@PathVariable long orderId, @RequestParam long amountCents) {
        Order order = orders.find(orderId);
        gateway.charge(amountCents);
        order.paid = true;
        orders.save(order);
        return order;
    }
    @PostMapping("/wallet/{accountId}/withdraw")
    long withdraw(@PathVariable long accountId, @RequestParam long amountCents) {
        Wallet wallet = orders.wallet(accountId);
        if (wallet.balance < amountCents) throw new IllegalArgumentException("insufficient funds");
        wallet.balance -= amountCents;
        orders.saveWallet(wallet);
        return wallet.balance;
    }
}
class Order { long id; long ownerId; long totalCents; boolean paid; }
class Wallet { long ownerId; long balance; }
interface OrderRepository {
    Order find(long id);
    void save(Order order);
    Wallet wallet(long id);
    void saveWallet(Wallet wallet);
}
interface PaymentGateway { void charge(long amountCents); }
