tl::expected<ChangeAddress, AddressResolutionError>
WalletTxBuilder::GetChangeAddress(
        CWallet& wallet,
        const ZTXOSelector& selector,
        const SpendableInputs& spendable,
        const Payments& resolvedPayments,
        const TransactionStrategy& strategy,
        bool afterNU5) const
{
    // Determine the account we're sending from.
    auto sendFromAccount = wallet.FindAccountForSelector(selector).value_or(ZCASH_LEGACY_ACCOUNT);
    auto getAllowedChangePools = [&](const std::set<ReceiverType>& receiverTypes) {
        std::set<OutputPool> result{resolvedPayments.GetRecipientPools()};
        // We always allow shielded change when not sending from the legacy account.
        if (sendFromAccount != ZCASH_LEGACY_ACCOUNT) {
            result.insert(OutputPool::Sapling);
        }
        for (ReceiverType rtype : receiverTypes) {
            switch (rtype) {
                case ReceiverType::P2PKH:
                case ReceiverType::P2SH:
                    if (strategy.AllowRevealedRecipients()) {
                        result.insert(OutputPool::Transparent);
                    }
                    break;
                case ReceiverType::Sapling:
                    if (!spendable.saplingNoteEntries.empty() || strategy.AllowRevealedAmounts()) {
                        result.insert(OutputPool::Sapling);
                    }
                    break;
                case ReceiverType::Orchard:
                    // FIX #7006: Allow Orchard output (typically change) when spending existing Orchard notes,
                    // even before NU5 activation / if afterNU5 is unexpectedly false.
                    // This prevents funds from getting stuck in spend-only scenarios.
                    // When no Orchard notes exist, Orchard output still requires NU5 + AllowRevealedAmounts
                    // to avoid unintended shielded Orchard creation pre-activation.
                    if (!spendable.orchardNoteMetadata.empty()
                        || (afterNU5 && strategy.AllowRevealedAmounts())) {
                        result.insert(OutputPool::Orchard);
                    }
                    break;
            }
        }
        return result;
    };

    auto changeAddressForTransparentSelector = [&](const std::set<ReceiverType>& receiverTypes)
        -> tl::expected<ChangeAddress, AddressResolutionError> {
        auto addr = wallet.GenerateChangeAddressForAccount(
                sendFromAccount,
                getAllowedChangePools(receiverTypes));
        if (addr.has_value()) {
            return {addr.value()};
        } else {
            return tl::make_unexpected(AddressResolutionError::TransparentChangeNotAllowed);
        }
    };

    auto changeAddressForSaplingAddress = [&](const libzcash::SaplingPaymentAddress& addr)
        -> RecipientAddress {
        // for Sapling, if using a legacy address, return change to the
        // originating address; otherwise return it to the Sapling internal
        // address corresponding to the UFVK.
        if (sendFromAccount == ZCASH_LEGACY_ACCOUNT) {
            return addr;
        } else {
            auto addr = wallet.GenerateChangeAddressForAccount(
                    sendFromAccount,
                    getAllowedChangePools({ReceiverType::Sapling}));
            assert(addr.has_value());
            return addr.value();
        }
    };

    auto changeAddressForZUFVK = [&](
            const ZcashdUnifiedFullViewingKey& zufvk,
            const std::set<ReceiverType>& receiverTypes) {
        auto addr = zufvk.GetChangeAddress(getAllowedChangePools(receiverTypes));
        assert(addr.has_value());
        return addr.value();
    };

    return examine(selector.GetPattern(), match {
        [&](const CKeyID&) {
            return changeAddressForTransparentSelector({ReceiverType::P2PKH});
        },
        [&](const CScriptID&) {
            return changeAddressForTransparentSelector({ReceiverType::P2SH});
        },
        [](const libzcash::SproutPaymentAddress& addr)
            -> tl::expected<ChangeAddress, AddressResolutionError> {
            // for Sprout, we return change to the originating address using the tx builder.
            return addr;
        },
        [](const libzcash::SproutViewingKey& vk)
            -> tl::expected<ChangeAddress, AddressResolutionError> {
            // for Sprout, we return change to the originating address using the tx builder.
            return vk.address();
        },
        [&](const libzcash::SaplingPaymentAddress& addr)
            -> tl::expected<ChangeAddress, AddressResolutionError> {
            return changeAddressForSaplingAddress(addr);
        },
        [&](const libzcash::SaplingExtendedFullViewingKey& fvk)
            -> tl::expected<ChangeAddress, AddressResolutionError> {
            return changeAddressForSaplingAddress(fvk.DefaultAddress());
        },
        [&](const libzcash::UnifiedAddress& ua)
            -> tl::expected<ChangeAddress, AddressResolutionError> {
            auto zufvk = wallet.GetUFVKForAddress(ua);
            assert(zufvk.has_value());
            return changeAddressForZUFVK(zufvk.value(), ua.GetKnownReceiverTypes());
        },
        [&](const libzcash::UnifiedFullViewingKey& fvk)
            -> tl::expected<ChangeAddress, AddressResolutionError> {
            return changeAddressForZUFVK(
                    ZcashdUnifiedFullViewingKey::FromUnifiedFullViewingKey(params, fvk),
                    fvk.GetKnownReceiverTypes());
        },
        [&](const AccountZTXOPattern& acct) -> tl::expected<ChangeAddress, AddressResolutionError> {
            return wallet.GenerateChangeAddressForAccount(
                    acct.GetAccountId(),
                    getAllowedChangePools(acct.GetReceiverTypes()))
                .map_error([](auto err) {
                    switch (err) {
                        case AccountChangeAddressFailure::DisjointReceivers:
                            return AddressResolutionError::CouldNotResolveReceiver;
                        case AccountChangeAddressFailure::TransparentChangeNotPermitted:
                            return AddressResolutionError::TransparentChangeNotAllowed;
                        case AccountChangeAddressFailure::NoSuchAccount:
                            throw std::runtime_error("Selector account doesn’t exist.");
                    }
                });
        }
    });
}
