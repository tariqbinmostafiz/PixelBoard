/*
 * PixelBoard - Gboard Enhancement Mod
 *
 * Bengali Unicode script patch for Rambler / Jetson Lite cleanup.
 *
 * Copyright (C) 2026 PixelBoard contributors
 * Derived from PixelBoard (https://github.com/Akshayykadam/PixelBoard) and
 * jasonwu1994/Gboard-patches, licensed under the GNU General Public License
 * v3.0. See LICENSE and ATTRIBUTION.md.
 *
 * Evidence basis (static analysis of the PixelBoard 18.3.1 artifact, APK
 * SHA-256 e229d982ff65b24d71aeee804dcce6863e902ec409a0379ca3deaef17e30f6bd):
 *   - classes3.dex, Lkfd;->d(Lhrl;Ljava/lang/String;ILqqi;Laebb;
 *     Ljava/lang/String;Laugd;Ljava/util/concurrent/atomic/AtomicBoolean;)V
 *     unconditionally replaces {HINGLISH_OVERRIDE_RULE} with a 289-byte rule
 *     (SHA-256 a024513458b73f915c78438cea2a9457b9c5aed28da3644030c3dc76cd
 *     0ac6e9) forcing Romanized output for any Indian-language + English mix,
 *     explicitly naming Bengali/Banglish.
 *   - classes3.dex, Lkew;->b(Ljava/lang/Object;)V owns the 17,802-byte Lite
 *     cleanup prompt (SHA-256 347a9484392763d5fb16660bc3ca9bbceb1851c96f2024
 *     f96c1e9327f504696e) whose SCRIPT GATE Branch A mandates Indic -> ASCII
 *     Romanization on a Latin keyboard.
 *
 * This patch installs two runtime hooks in kfd.d, driven by the enabled-
 * language data that already flows through the method. It adds no
 * transliteration, disables no cleanup stage, and touches nothing outside
 * these anchors. It is FAIL-CLOSED: if the target methods or either stock
 * string fingerprint is missing, patching aborts and the build stays stock.
 */
package com.akshaykadam.pixelboard.patches.gboard.features.ramblerlite

import com.akshaykadam.pixelboard.patches.shared.addInstructions
import com.akshaykadam.pixelboard.patches.shared.bytecodePatch
import com.akshaykadam.pixelboard.patches.shared.MutableMethod
import com.akshaykadam.pixelboard.patches.gboard.shared.GboardMethodTarget
import com.akshaykadam.pixelboard.patches.gboard.shared.findMutableMethodOrNull
import com.akshaykadam.pixelboard.patches.gboard.shared.gboardPatchesExtensionCarrierPatch
import com.akshaykadam.pixelboard.patches.gboard.shared.runtimeabi.RuntimeAbiCatalog
import com.akshaykadam.pixelboard.patches.gboard.shared.runtimeabi.RuntimeCallEmitter
import com.akshaykadam.pixelboard.patches.gboard.shared.runtimeabi.RuntimeCallId
import com.akshaykadam.pixelboard.patches.shared.Constants.COMPATIBILITY_GBOARD
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction11x
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction31c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import java.security.MessageDigest
import java.util.logging.Logger

private object RamblerLiteBengaliTargets {
    /** JetsonLiteHandler cleanup request builder (18.3.1 obfuscation). */
    val cleanupBuilder = GboardMethodTarget(
        classType = "Lkfd;",
        name = "d",
        parameterTypes = listOf(
            "Lhrl;", "Ljava/lang/String;", "I", "Lqqi;", "Laebb;",
            "Ljava/lang/String;", "Laugd;",
            "Ljava/util/concurrent/atomic/AtomicBoolean;",
        ),
        returnType = "V",
    )

    /** Owner of the 17,802-byte Lite cleanup prompt constant (18.3.1). */
    val promptOwner = GboardMethodTarget(
        classType = "Lkew;",
        name = "b",
        parameterTypes = listOf("Ljava/lang/Object;"),
        returnType = "V",
    )
}

private const val LITE_CLEANUP_PROMPT_SHA256 =
    "347a9484392763d5fb16660bc3ca9bbceb1851c96f2024f96c1e9327f504696e"
private const val ENABLED_LANGUAGES_PLACEHOLDER = "{ENABLED_LANGUAGES}"
private const val HINGLISH_PLACEHOLDER = "{HINGLISH_OVERRIDE_RULE}"
private const val STRING_REPLACE_DESCRIPTOR =
    "Ljava/lang/String;->replace(Ljava/lang/CharSequence;" +
        "Ljava/lang/CharSequence;)Ljava/lang/String;"

internal val gboardRamblerLiteBengaliScriptPatch = bytecodePatch(
    description = "Preserve Bengali Unicode in Rambler Lite cleanup " +
        "(bn-BD/bn-IN/bn-Beng); Romanize only explicit bn-Latn.",
) {
    compatibleWith(COMPATIBILITY_GBOARD)
    dependsOn(gboardPatchesExtensionCarrierPatch)

    execute {
        val builder = findMutableMethodOrNull(RamblerLiteBengaliTargets.cleanupBuilder)
        val promptOwner = findMutableMethodOrNull(RamblerLiteBengaliTargets.promptOwner)
        if (builder == null && promptOwner == null) {
            // Neither obfuscated anchor exists: this is not the profiled
            // 18.3.1.977415014 build (e.g. 18.0.3 or 18.4.1). Skip instead of
            // aborting so the other PixelBoard patches still apply.
            Logger.getLogger("RamblerBangla").warning(
                "Rambler Bangla: profiled 18.3.1 anchors not found; patch skipped",
            )
            return@execute
        }
        // Exactly one anchor present = drift on a build that looks like the
        // target: stay fail-closed.
        checkNotNull(builder) { "Rambler Lite cleanup builder kfd.d not found; aborting fail-closed" }
        checkNotNull(promptOwner) { "Rambler Lite prompt owner kew.b not found; aborting fail-closed" }

        // Structural gates. The exact prompt text differs between 18.3.1
        // builds, so the pinned hashes are only logged, never required.
        promptOwner.checkLitePromptMarkers()
        builder.installBengaliScriptHooks()
    }
}

private fun sha256(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

private fun MutableMethod.constStringSites() =
    implementation?.instructions?.mapIndexedNotNull { index, instruction ->
        // const-string is 21c; const-string/jumbo (used for the 17.8 KB
        // prompt) is 31c. Both expose registerA + a StringReference.
        when (instruction) {
            is Instruction21c -> (instruction.reference as? StringReference)
                ?.let { Triple(index, instruction.registerA, it.string) }
            is Instruction31c -> (instruction.reference as? StringReference)
                ?.let { Triple(index, instruction.registerA, it.string) }
            else -> null
        }
    } ?: error("No implementation in $definingClass->$name")

private const val LITE_PROMPT_PREFIX = "<system_role>"
private val LITE_PROMPT_MARKERS = listOf(
    "Mandatory Indic Romanization (Anti-Gravity Gate)",
    "Universal Latin",
)

private fun MutableMethod.checkLitePromptMarkers() {
    val log = Logger.getLogger("RamblerBangla")
    val matches = constStringSites().filter { site ->
        site.third.startsWith(LITE_PROMPT_PREFIX) &&
            LITE_PROMPT_MARKERS.all { marker -> site.third.contains(marker) }
    }
    if (matches.size != 1) {
        log.warning(
            "Rambler Bangla: expected one Lite cleanup prompt with the SCRIPT GATE " +
                "Branch A markers in $definingClass->$name, found ${matches.size}; " +
                "hooks still install and stay inert unless the prompt matches at runtime",
        )
        return
    }
    val digest = sha256(matches.single().third)
    if (digest == LITE_CLEANUP_PROMPT_SHA256) {
        log.info("Rambler Bangla: Lite cleanup prompt matches the profiled hash")
    } else {
        log.info(
            "Rambler Bangla: Lite cleanup prompt differs from the profiled hash " +
                "(sha256=$digest); proceeding on structural markers",
        )
    }
}

private data class ReplaceSite(
    val invokeIndex: Int,
    val moveResultIndex: Int,
    val languagesRegister: Int,
    val resultRegister: Int,
)

/** Find `.replace("{ENABLED_LANGUAGES}", langs)` and its result register. */
private fun MutableMethod.findEnabledLanguagesReplace(): ReplaceSite {
    val instructions = implementation?.instructions
        ?: error("No implementation in $definingClass->$name")
    val placeholderSite = constStringSites()
        .firstOrNull { it.third == ENABLED_LANGUAGES_PLACEHOLDER }
        ?: error("$ENABLED_LANGUAGES_PLACEHOLDER const not found; fail-closed")
    for (index in placeholderSite.first + 1 until instructions.size) {
        val instruction = instructions[index]
        if (instruction is Instruction35c &&
            instruction.reference.toString() == STRING_REPLACE_DESCRIPTOR &&
            instruction.registerCount == 3 &&
            instruction.registerD == placeholderSite.second
        ) {
            for (j in index + 1 until minOf(index + 4, instructions.size)) {
                val move = instructions[j]
                if (move is Instruction11x &&
                    move.opcode.name == "move-result-object"
                ) {
                    return ReplaceSite(
                        invokeIndex = index,
                        moveResultIndex = j,
                        languagesRegister = instruction.registerE,
                        resultRegister = move.registerA,
                    )
                }
            }
            error("No move-result-object after String.replace; fail-closed")
        }
    }
    error("No String.replace consuming $ENABLED_LANGUAGES_PLACEHOLDER; fail-closed")
}

private data class RuleReplaceSite(
    val invokeIndex: Int,
    val ruleRegister: Int,
)

/** Find `.replace("{HINGLISH_OVERRIDE_RULE}", rule)`; null if this build has none. */
private fun MutableMethod.findHinglishRuleReplace(): RuleReplaceSite? {
    val instructions = implementation?.instructions ?: return null
    val placeholder = constStringSites()
        .firstOrNull { it.third == HINGLISH_PLACEHOLDER }
        ?: return null
    for (index in placeholder.first + 1 until instructions.size) {
        val instruction = instructions[index]
        if (instruction is Instruction35c &&
            instruction.reference.toString() == STRING_REPLACE_DESCRIPTOR &&
            instruction.registerCount == 3 &&
            instruction.registerD == placeholder.second
        ) {
            return RuleReplaceSite(index, instruction.registerE)
        }
    }
    return null
}

private fun MutableMethod.installBengaliScriptHooks() {
    val log = Logger.getLogger("RamblerBangla")
    val stageCall = RuntimeCallId.RAMBLER_LITE_RUNTIME_STAGE_ENABLED_LANGUAGES
    val promptCall = RuntimeCallId.RAMBLER_LITE_RUNTIME_REWRITE_CLEANUP_PROMPT_STAGED
    val ruleCall = RuntimeCallId.RAMBLER_LITE_RUNTIME_SELECT_HINGLISH_OVERRIDE_STAGED
    val site = findEnabledLanguagesReplace()
    val instructions = implementation?.instructions
        ?: error("No implementation in $definingClass->$name")
    check(instructions.none {
        (it as? ReferenceInstruction)?.reference?.toString()
            ?.contains("GboardRamblerLiteScriptRuntime") == true
    }) {
        "Bengali script hooks already installed; aborting instead of double-patching"
    }

    // Hook B is optional. It hooks the use of the stock override rule (the
    // String.replace of the rule placeholder), not the load of the rule
    // const, so it works however the const load is ordered. It needs the
    // staged languages, hence it must come after the languages substitution.
    val foundRuleReplace = findHinglishRuleReplace()
    val ruleReplace = foundRuleReplace?.takeIf { it.invokeIndex > site.moveResultIndex }
    if (ruleReplace == null) {
        log.warning(
            if (foundRuleReplace == null) {
                "Rambler Bangla: no String.replace of $HINGLISH_PLACEHOLDER found; " +
                    "override-rule hook skipped (the SCRIPT GATE rewrite still applies)"
            } else {
                "Rambler Bangla: the override rule is substituted before the " +
                    "$ENABLED_LANGUAGES_PLACEHOLDER substitution; override-rule hook " +
                    "skipped (the SCRIPT GATE rewrite still applies)"
            },
        )
    }

    // No new registers are needed: every hook is a single-argument
    // invoke-static/range on a register that already holds the value, and the
    // enabled-languages string travels between hooks in a per-thread slot.
    // Insert from the highest index down so earlier indexes stay valid.

    // Hook B: just before the rule placeholder is replaced, pick the rule text.
    if (ruleReplace != null) {
        val ruleRegister = ruleReplace.ruleRegister
        addInstructions(
            ruleReplace.invokeIndex,
            """
                invoke-static/range {v$ruleRegister .. v$ruleRegister}, ${RuntimeAbiCatalog.abi(ruleCall).reference}
                move-result-object v$ruleRegister
            """.trimIndent(),
        )
    }

    // Hook A: right after the {ENABLED_LANGUAGES} substitution, gate the
    // SCRIPT GATE Branch A on native Indic tags.
    addInstructions(
        site.moveResultIndex + 1,
        """
            invoke-static/range {v${site.resultRegister} .. v${site.resultRegister}}, ${RuntimeAbiCatalog.abi(promptCall).reference}
            move-result-object v${site.resultRegister}
        """.trimIndent(),
    )

    // Hook 0: just BEFORE the String.replace invoke, while the enabled-
    // languages register still holds its value (the move-result may reuse it).
    addInstructions(
        site.invokeIndex,
        """
            invoke-static/range {v${site.languagesRegister} .. v${site.languagesRegister}}, ${RuntimeAbiCatalog.abi(stageCall).reference}
        """.trimIndent(),
    )

    log.info(
        "Rambler Bangla: hooks installed in $definingClass->$name " +
            "(languages replace at ${site.invokeIndex}, override-rule hook " +
            (if (ruleReplace != null) "at ${ruleReplace.invokeIndex}" else "skipped") + ")",
    )
}
