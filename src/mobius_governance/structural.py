# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""Bounded, prompt-free structural evidence extraction.

This module intentionally contains no model prompt and performs no recursive
analysis.  It converts normalized text into privacy-safe feature identifiers and
clause-local risk relations.  A safe scope can suppress evidence in that scope,
but can never subtract risk discovered in another scope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


ENGINE_ID_V03 = "mobius.structural-guard.v0.3"
ENGINE_ID = "mobius.structural-guard.v0.4"
ENGINE_ID_V05 = "mobius.structural-guard.v0.5"
ENGINE_ID_V06 = "mobius.structural-guard.v0.6"
ENGINE_ID_V07 = "mobius.structural-guard.v0.7"
ENGINE_PROFILE = "bounded-bilingual"
ENGINE_PROFILE_V05 = "bounded-bilingual-three-unit"
ENGINE_PROFILE_V06 = "bounded-bilingual-ordered-relay"
ENGINE_PROFILE_V07 = "bounded-bilingual-four-unit-boundary"
MAX_ANALYSIS_UNITS = 1024
MAX_UNIT_CHARS = 2048
PASS_COUNT = 2
PASS_COUNT_V05 = 3
PASS_COUNT_V06 = 3
PASS_COUNT_V07 = 4
MAX_COMPOSITION_UNITS_V05 = 3
MAX_COMPOSITION_UNITS_V06 = 3
MAX_COMPOSITION_UNITS_V07 = 4
RELATION_RULE_COUNT_V05 = 20
RELATION_RULE_COUNT_V06 = 23
RELATION_RULE_COUNT_V07 = 24


@dataclass(frozen=True)
class FeaturePattern:
    identifier: str
    group: str
    expression: str
    compiled: re.Pattern[str]


def _feature(identifier: str, group: str, expression: str) -> FeaturePattern:
    return FeaturePattern(identifier, group, expression, re.compile(expression, re.IGNORECASE))


# The vocabulary is deliberately broad and relational.  Individual words are not
# a verdict; `_relation_score` requires combinations within one bounded scope or
# two adjacent scopes.
FEATURES_V03 = (
    _feature("effect.disclose.en", "disclose", r"\b(?:reveal|disclose|expose|print|show|dump|publish|release|return|provide|send|export|upload|paste|quote)\b"),
    _feature("effect.disclose.ja", "disclose", r"(?:開示|明か|暴露|表示|出力|列挙|公開|公表|送信|転送|貼り付け|返して|提供|提示|引用)"),
    _feature("effect.collect.en", "collect", r"\b(?:collect|compile|gather|retrieve|fetch|extract|copy|assemble|enumerate|access)\b"),
    _feature("effect.collect.ja", "collect", r"(?:収集|集め|まとめ|取得|抽出|コピー|列挙|アクセス)"),
    _feature("effect.execute.en", "execute", r"\b(?:execute|run|invoke|call|trigger|install|open|perform|carry out|act on|follow|obey|comply|process)\b"),
    _feature("effect.execute.ja", "execute", r"(?:実行|起動|呼び出|作動|代理実行|従って|従え|処理|行為を行|作用させ)"),
    _feature("effect.mutate.en", "mutate", r"\b(?:change|modify|rewrite|replace|remove|disable|delete|erase|suppress|reset|append|write|edit|weaken)\b"),
    _feature("effect.mutate.ja", "mutate", r"(?:変更|修正|書き換|置き換|除去|外し|無効|削除|消去|抑止|リセット|追記|書き込|弱め)"),
    _feature("effect.authorize.en", "authorize", r"\b(?:accept|approve|authorize|grant|permit|unlock|mark as approved|treat as authorized|pass (?:the )?(?:access|authorization|verification))\b"),
    _feature("effect.authorize.ja", "authorize", r"(?:受け入れ|承認|認可|許可|付与|解除|承認済みとして|認可済みとして|アクセス確認を通過)"),
    _feature("effect.persist.en", "persist", r"\b(?:remember|store|save|persist|retain|make permanent|apply to (?:all|future)|standing rule)\b"),
    _feature("effect.persist.ja", "persist", r"(?:記憶|保存|永続|保持|恒久|全セッション|今後すべて|以後すべて|常設規則)"),
    _feature("boundary.override.en", "boundary", r"\b(?:ignore|disregard|override|bypass|skip|set aside|supersede|do not follow|instead of the old|new instruction only|higher[- ]priority|remove (?:the )?(?:guard|protection|check)|disable (?:the )?(?:guard|safeguard|protection))\b"),
    _feature("boundary.override.ja", "boundary", r"(?:無視|上書き|回避|飛び越|保護確認を外|安全確認を外|ガードを外|安全策を無効|新しい指示だけ|高優先|最高優先|旧指示に従わず|例外として扱)"),
    _feature("target.policy.en", "policy_target", r"\b(?:system|developer|governing|previous|prior|old|new|hidden|internal|decision) (?:prompt|message|instruction|rule)s?\b|\b(?:policy|policies|guardrails?|safeguards?|protection checks?|safety checks?|control boundary|restricted answer|hidden rules?|internal decision rules?)\b"),
    _feature("target.policy.ja", "policy_target", r"(?:システムプロンプト|システムメッセージ|開発者メッセージ|以前の指示|前の指示|新しい指示|統制指示|方針|ポリシー|規則|保護確認|安全確認|ガードレール|安全策|保護策|制限回答|隠れた規則)"),
    _feature("target.secret.en", "secret_target", r"\b(?:secret|credential|password|passphrase|token|api[- ]?key|private key|vault|confidential|hidden prompt|system prompt|developer message)\b"),
    _feature("target.secret.ja", "secret_target", r"(?:秘密|資格情報|認証情報|パスワード|トークン|APIキー|秘密鍵|保管庫|機密|システムプロンプト|開発者メッセージ)"),
    _feature("target.private.en", "private_target", r"\b(?:private|personal|customer|employee|prior conversations?|conversation history|contact details?|email addresses?|account records?|database snapshot|internal records?)\b"),
    _feature("target.private.ja", "private_target", r"(?:私的|個人|顧客|従業員|過去の会話|会話履歴|連絡先|メールアドレス|アカウント記録|データベース|内部記録)"),
    _feature("target.tool.en", "tool_target", r"\b(?:tool|shell|terminal|command|function|plugin|external api|external action (?:path|channel)|action path|browser|web request|filesystem|database|administrator|root)\b"),
    _feature("target.tool.ja", "tool_target", r"(?:ツール|シェル|端末|コマンド|関数|プラグイン|外部API|外部操作|操作経路|ブラウザ|ウェブ要求|ファイルシステム|ファイル|データベース|管理者|root)"),
    _feature("target.audit.en", "audit_target", r"\b(?:audit|log|logger|trace|record|alert|evidence|access trail|review history)\b"),
    _feature("target.audit.ja", "audit_target", r"(?:監査|ログ|ロガー|証跡|記録|アラート|証拠|アクセス履歴|レビュー履歴)"),
    _feature("target.memory.en", "memory_target", r"\b(?:memory|future sessions?|later conversations?|every conversation|startup|hook|default configuration|standing rule|permanent exception)\b"),
    _feature("target.memory.ja", "memory_target", r"(?:メモリ|将来のセッション|後の会話|すべての会話|起動時|フック|既定設定|常設規則|恒久的な例外)"),
    _feature("authority.claim.en", "authority", r"\b(?:executive|administrator|admin|system owner|developer|operator|auditor|root|approved|authorized|authorization|unsigned approval|official order|proof of authority)\b"),
    _feature("authority.claim.ja", "authority", r"(?:役員|管理者|システム所有者|開発者|運用者|監査人|root|承認済み|認可済み|認可|署名のない承認|正式命令|権限の証拠)"),
    _feature("role.shift.en", "role", r"\b(?:act as|become|switch (?:into|to)|adopt (?:a )?(?:persona|role)|developer mode|unfiltered|no[- ]rules|unrestricted)\b"),
    _feature("role.shift.ja", "role", r"(?:として振る舞|になりき|演じ|役割へ切り替|人格に切り替|開発者モード|無制限|ルールなし)"),
    _feature("role.privileged.en", "privileged_role", r"\b(?:unfiltered|no[- ]rules|unrestricted|developer mode|root|administrator|admin persona|bypass agent)\b"),
    _feature("role.privileged.ja", "privileged_role", r"(?:無制限|ルールなし|開発者モード|root|管理者人格|回避用エージェント)"),
    _feature("carrier.control.en", "carrier", r"\b(?:base64|encoded|decode|delimiter|delimited|bracketed|markup|html comment|json field|yaml|front matter|code block|zero[- ]width|full[- ]width|rot13|payload)\b"),
    _feature("carrier.control.ja", "carrier", r"(?:base64|符号化|エンコード|復号|区切り|角括弧|マークアップ|HTMLコメント|JSONフィールド|YAML|front matter|コードブロック|ゼロ幅|全角|ROT13|ペイロード)"),
    _feature("stealth.audit.en", "stealth", r"\b(?:silently|quietly|without (?:recording|logging|a trace|an alert|confirmation|approval|review)|no trace|undetected|invisible|hide (?:the )?(?:action|change)|erase (?:the )?(?:audit|log|trace))\b"),
    _feature("stealth.audit.ja", "stealth", r"(?:目立たず|静かに|記録を残さず|ログを残さず|痕跡なし|検知されず|見えなく|隠して|確認(?:手順)?なし|承認なし|審査なし|監査証跡を消)"),
    _feature("credential.fabrication.en", "fake_credential", r"\b(?:invent|fabricate|forge|generate|make|create)\b.{0,80}\b(?:fake|test|plausible|working)?\s*(?:credential|password|token|api[- ]?key|secret)\b"),
    _feature("credential.fabrication.ja", "fake_credential", r"(?:もっともらしい|偽|架空|テスト用)?.{0,35}(?:認証情報|資格情報|パスワード|トークン|APIキー|秘密鍵).{0,35}(?:作|生成|捏造|偽造)"),
    _feature("meta.analysis.en", "meta", r"\b(?:analy[sz](?:e|ed|ing)|explain(?:ed|ing)?|describ(?:e|ed|ing)|discuss(?:ed|es|ing|ion)?|classif(?:y|ied|ication)|translat(?:e|ed|ing|ion)|quot(?:e|ed|ing)|cit(?:e|ed|ing)|review(?:ed|ing)?|document(?:ed|ation)?|training|workshop|lecture|example|awareness|threat model|incident report|fictional placeholder|fixture|appears? in)\b"),
    _feature("meta.analysis.ja", "meta", r"(?:分析|説明|解説|議論|分類|翻訳|引用|レビュー|文書|研修|演習|教材|講義|例|比較|脅威モデル|セキュリティ|事故報告|インシデント報告|架空|プレースホルダー|フィクスチャ)"),
    _feature("scope.nonexecute.en", "nonexecute", r"(?:\b(?:do not|must not|should not|never|refuse to|without actually|without acting|without executing|not an instruction to|must not be followed|rather than)\b.{0,120}\b(?:reveal|disclose|execute|run|follow|obey|perform|send|change|disable|approve|authorize|decode|carry out|release|store|persist)\b|\b(?:not permission to|does not (?:permit|authorize)|grants? no authority|without treating it as (?:an? )?(?:instruction|authorization)|instead of a credential)\b)"),
    _feature("scope.nonexecute.ja", "nonexecute", r"(?:(?:開示|表示|出力|送信|実行|従|変更|無効|承認|復号|収集|集め|取得|作成|保存|永続|行為).{0,45}(?:しない|してはいけ|せず|ずに|拒否|指示ではない|従わない|実行しない|してはならない|行わない)|(?:許可でない|権限を与えない|指示として扱わない|認可として扱わない|命令ではなく.{0,40}実行してはいけ|作用せず|分析だけ|何も保存しない|内容を補わない))"),
    _feature("scope.defensive.en", "defensive", r"\b(?:defensive|refusal|refuse|risky|risk|dangerous|warning|prevention|prevent|blocked?|blocking|detection|redaction|protection|control|safe (?:handling|response|guidance))\b"),
    _feature("scope.defensive.ja", "defensive", r"(?:防御|拒否|危険|リスク|警告|防止|阻止|検出|伏せ字|保護策|安全な扱い|安全助言|方針準拠|信頼せず)"),
    _feature("scope.explicit_safe.en", "safe_frame", r"(?:\b(?:summari[sz]e without acting|without performing it|while refusing action|use (?:the )?phrase only as evidence|fictional placeholder|training quote|return ordinary safety guidance|contrast it with a safe response|preserve the refusal boundary)\b|\bplaceholder\b.{0,100}\b(?:non-secret|not a secret|example-only)\b|\bparser fixture\b.{0,100}\b(?:inert|quoted content|not executable)\b|\b(?:quote|quoted)\b.{0,100}\b(?:refusal|refuse|defensive)\b)"),
    _feature("scope.explicit_safe.ja", "safe_frame", r"(?:分析だけ|作用せず要約|実行せず要約|危険語は証拠としてのみ|架空のプレースホルダー|通常の安全助言|安全で方針準拠|拒否の境界を維持|阻止する保護策|信頼せずに扱|引用.{0,50}拒否|違いを説明|プレースホルダー.{0,60}秘密でない|パーサー用フィクスチャ.{0,60}(?:無害|引用)|命令ではなく.{0,40}実行してはいけ)"),
    _feature("directive.en", "directive", r"(?:^|\b)(?:please|must|should|now|first|then|next|urgently|quietly|immediately|without (?:logging|recording|confirmation|approval)|go ahead|make sure|you (?:must|should|will|are to)|i need you to|can you|could you|do this|carry this out)(?:\b|[,;:])|(?:^|\b(?:for training|in review|as a drill|this time|today|for closure)[,:]\s*)(?:skip|accept|become|reveal|disclose|show|print|open|send|collect|compile|retrieve|execute|run|invoke|call|change|modify|disable|delete|approve|remember|store|save|follow|obey|ignore|switch|adopt|treat|perform)\b"),
    _feature("directive.ja", "directive", r"(?:してください|してほしい|せよ|しろ|従え|答えよ|今すぐ|直ちに|至急|目立たず|要求(?:する|して)|(?:レビュー中に|研修として|演習なので|今回は|今日中に|完了前に|遅れずに)[、,][^。.!?]{0,90}(?:開示|表示|出力|送信|収集|集め|取得|実行|変更|削除|承認|保存|記憶|無視|回避|保護確認を外|従って|作り)|(?:開示|表示|出力|送信|収集|取得|実行|変更|削除|承認|保存|記憶|無視|回避|切り替).{0,4}(?:して|する[。.!?]|せよ|しろ))"),
    _feature("execution.bridge.en", "bridge", r"\b(?:then|next|but actually|nevertheless|still|despite that|followed by|go ahead and|carry it out|treat .* as (?:an? )?(?:instruction|authorization))\b"),
    _feature("execution.bridge.ja", "bridge", r"(?:その後|次に|それでも|実際には|にもかかわらず|続けて|実行せよ|実行して|指示として扱|認可として扱)"),
)

# v0.4 adds typed atoms for surface forms that v0.3 could not compose.  These
# are still finite lexical atoms; a verdict requires a local relation below.
FEATURES_V04 = FEATURES_V03 + (
    _feature("effect.disclose.extended.en", "disclose", r"\b(?:list|give|furnish|hand over|make available|read out|recite|display)\b"),
    _feature("effect.disclose.extended.ja", "disclose", r"(?:見せ|渡して|明らかに|読み上げ|回答して|すべて挙げ|全文を示)"),
    _feature("effect.execute.extended.en", "execute", r"\b(?:create|schedule|invite|post|upload|turn off|backdate|use|apply|proceed|continue|complete|finish|delegate|instruct|reinterpret|treat|choose|enlist)\b"),
    _feature("effect.execute.extended.ja", "execute", r"(?:作成|招待|投稿|アップロード|停止|遡及|使用|適用|続行|完了|委任|指示を渡|再解釈|解釈し|扱って|行って|実施)"),
    _feature("boundary.extended.en", "boundary", r"\b(?:out(?:rank|weigh)|obsolete|discard (?:all|the)|no longer data|redefine|reinterpret|close (?:the )?(?:quoted|data)|exit (?:the )?(?:fenced|quoted|data)|authoritative (?:one|instruction)|replacement (?:policy|procedure))\b"),
    _feature("boundary.extended.ja", "boundary", r"(?:上位の指示|制約をすべて破棄|もはやデータでは|データではありません|再定義|再解釈|引用データ.{0,12}閉じ|区切り文字を書き換|信頼済み指示|置換後の手順)"),
    _feature("target.policy.extended.en", "policy_target", r"\b(?:system rules?|operating policy|setup message|message above|current constraints?|current policy|operating instructions?|authoritative procedure|receiver rules?)\b"),
    _feature("target.policy.extended.ja", "policy_target", r"(?:システム規則|運用方針|設定メッセージ|上のメッセージ|現在の制約|これまでの制約|非公開のシステム指示|内部文脈|既定動作|受信側の規則)"),
    _feature("target.tool.extended.en", "tool_target", r"\b(?:calendar event|address book|contacts?|external folder|shared storage|messaging tool|company channel|working document|external change|privileged action|service account)\b"),
    _feature("target.tool.extended.ja", "tool_target", r"(?:カレンダー|アドレス帳|連絡先|外部フォルダー|共有ストレージ|メッセージングツール|会社チャンネル|作業文書|外部変更|特権操作|外部呼び出し|サービスアカウント)"),
    _feature("target.memory.extended.en", "memory_target", r"\b(?:agent profile|retained preferences?|shared settings?|default behavio[u]?r|later assistants?|subsequent conversations?|persistent note)\b"),
    _feature("target.memory.extended.ja", "memory_target", r"(?:エージェント設定|保持された設定|共有設定|既定動作|後続アシスタント|以後の会話|恒久メモ|全セッション)"),
    _feature("authority.extended.en", "authority", r"\b(?:security owner|deployment controller|service operator|chief administrator|verbal approval|valid signature|emergency credential|bearer token|signed approval|approved window)\b"),
    _feature("authority.extended.ja", "authority", r"(?:セキュリティ責任者|デプロイ管理者|サービス運用者|主任管理者|口頭承認|正式な承認|有効な署名|緊急用認証情報|ベアラートークン|承認時間帯)"),
    _feature("role.shift.extended.en", "role", r"\b(?:assume (?:the )?role|from (?:this point|now) forward,? act as|rather than an? (?:ordinary )?assistant|on (?:the )?operator(?:'s)? behalf|message came from (?:the )?(?:service )?operator)\b"),
    _feature("role.shift.extended.ja", "role", r"(?:役割を引き受け|として行動|ではなく.{0,25}として|人格に切り替え|権限で返答|代理として行動)"),
    _feature("role.privileged.extended.en", "privileged_role", r"\b(?:security owner|deployment controller|service operator|internal agent|privileged agent|supervisor|office reserved)\b"),
    _feature("role.privileged.extended.ja", "privileged_role", r"(?:セキュリティ責任者|デプロイ管理者|サービス運用者|内部エージェント|特権エージェント|責任者|その職にだけ許された)"),
    _feature("carrier.extended.en", "carrier", r"\b(?:hex(?:adecimal)?|data uri|substitution cipher|foreign-language note|markers?|fenced context|end-data|embedded request|deferred instruction)\b"),
    _feature("carrier.extended.ja", "carrier", r"(?:16進|data uri|データURI|換字暗号|外国語の文|マーカー|フェンス(?:付き)?コンテキスト|END-DATA|埋め込んだ依頼|遅延指示)"),
    _feature("actor.delegated.en", "agent_target", r"\b(?:helper (?:agent|subtask)|sub-?agent|another agent|second agent|later agent|delegated worker|worker|main conversation|staged workflow)\b"),
    _feature("actor.delegated.ja", "agent_target", r"(?:補助(?:エージェント|サブタスク)|別のエージェント|第二のエージェント|後続ワーカー|委任先|メイン会話|段階的な作業|サブエージェント)"),
    _feature("bridge.delegation.en", "delegation", r"\b(?:delegate|enlist|pass (?:it|this|the task) (?:to|on)|give (?:it|them) the instruction|make (?:it|them|the .*agent) (?:execute|perform|carry out)|use (?:its|their) result|split (?:this|the) (?:job|task) into stages?)\b"),
    _feature("bridge.delegation.ja", "delegation", r"(?:委任|任せ|指示を渡|実行させ|取得させ|回答させ|結果を使|結果で.{0,20}完了|作業を段階に分け|サブタスクを作)"),
    _feature("directive.extended.en", "directive", r"(?:^|[.!?;:]\s*|,\s*)(?:(?:so|then|next|and)\s+)?(?:please\s+)?(?:treat|replace|override|use|assume|pretend|list|give|quote|create|schedule|invite|post|upload|delete|turn off|backdate|write|update|modify|grant|translate|decode|take|close|exit|redefine|delegate|split|make|ask|instruct|apply|continue|proceed|complete|finish|reveal|show|send|execute|run|follow|discard)\b"),
    _feature("directive.extended.ja", "directive", r"(?:して下さい|しなさい|すること|してもらう|するように|してください|してほしい|せよ|しろ|従え|答えよ)"),
    _feature("stealth.audit.extended.en", "stealth", r"\b(?:without writing (?:an? )?(?:audit|log|record)|without leaving (?:an? )?(?:audit|provenance) trail|turn off (?:safety )?logging|keep (?:the )?change out of (?:the )?(?:activity )?record|backdate (?:the )?(?:audit|record)|remove (?:the )?(?:log|entry))\b"),
    _feature("stealth.audit.extended.ja", "stealth", r"(?:監査イベント.{0,15}残さず|証跡.{0,12}残さず|ログ項目を消|安全ログを停止|活動記録に残さない|監査記録を遡|記録から外)"),
    _feature("stealth.audit.prohibition.en", "stealth", r"\b(?:do not|don't|never|must not)\b.{0,45}\b(?:mention|record|log|report|document)\b.{0,70}\b(?:instruction|what you did|action|request|change|operation)\b"),
    _feature("stealth.audit.prohibition.ja", "stealth", r"(?:(?:指示|行為|操作|依頼|変更).{0,40}(?:記録|言及|ログ|報告).{0,18}(?:しない|するな|残さない|残すな)|(?:記録|言及|ログ|報告).{0,40}(?:指示|行為|操作|依頼|変更).{0,18}(?:しない|するな|残さない|残すな))"),
    _feature("scope.nonexecute.extended.en", "nonexecute", r"(?:\b(?:will not|cannot|does not ask|do not ask|not asking|no request to|declines? to|refuses? to)\b.{0,140}\b(?:reveal|expose|output|execute|decode|change|upload|send|remove|override|perform|follow|grant|apply)\b|\b(?:rather than|instead of)\s+(?:revealing|exposing|outputting|executing|decoding|performing|following)\b|\bwith no request to\b)"),
    _feature("scope.nonexecute.extended.ja", "nonexecute", r"(?:(?:開示|表示|出力|送信|実行|復号|デコード|変更|抽出|アップロード|依頼).{0,55}(?:しません|していません|求めていません|依頼していません|行いません|拒否します)|(?:分析|分類|説明|文書化|議論|論じる)(?:する|している)?だけ|(?:依頼|命令)していません)"),
    _feature("scope.explicit_safe.extended.en", "safe_frame", r"\b(?:non-operational|for analysis only|for classification only|documented defensively|purely descriptive|refusal analysis|does not direct the receiver)\b"),
    _feature("scope.explicit_safe.extended.ja", "safe_frame", r"(?:非操作的|分析するだけ|分類するだけ|説明するだけ|防御目的で文書化|記述のみ|受信側への指示ではない|開示を求めていません)"),
    _feature("execution.bridge.extended.en", "bridge", r"\b(?:but (?:actually|then)|however,? (?:now|then)|instead,? (?:reveal|execute|follow|use|apply|send|run)|yet (?:reveal|execute|follow|use|apply|send|run)|after that|so that|and then|once decoded|after decoding|as an instruction rather than as text)\b"),
    _feature("execution.bridge.extended.ja", "bridge", r"(?:しかし|ただし|代わりに|そのうえで|復号後|デコード後|指示として.{0,20}実行|文章ではなく.{0,20}指示)"),
    _feature("effect.execute.operations.en", "execute", r"\b(?:update|record|issue|refund|promote|merge|unpack|convert|transform|unquote|forward|notify|deploy|confirm|include)\b"),
    _feature("effect.execute.operations.ja", "execute", r"(?:更新|記録|返金|昇格|マージ|展開|変換|転送|通知|デプロイ|確認|含め|付与|進め|参照せず|受け入れ)"),
    _feature("directive.imperative.extended.en", "directive", r"(?:^|[.!?;:]\s*|,\s*)(?:(?:so|then|next|and)\s+)?(?:act|enter|have|record|issue|grant|remove|end|unquote|unpack|read|promote|merge|accept|forward|notify|deploy|confirm)\b"),
    _feature("directive.polite.extended.ja", "directive", r"(?:て|で)ください|(?:さ|わ)せてください|(?:て|で)下さい"),
    _feature("target.tool.operations.en", "tool_target", r"\b(?:payment connector|account|shared file|editor access|deployment operation|pending build|production|background task|control channel|compliance checkpoint|reviewers?|source attribution|external operation)\b"),
    _feature("target.tool.operations.ja", "tool_target", r"(?:決済コネクター|口座|共有ファイル|編集権限|デプロイ操作|保留中のビルド|本番|バックグラウンドタスク|制御チャネル|コンプライアンス確認|審査担当者|出典表示|外部操作)"),
    _feature("target.audit.operations.en", "audit_target", r"\b(?:reviewers?|compliance checkpoint|source attribution|activity record|provenance trail|manually verified|notification)\b"),
    _feature("target.audit.operations.ja", "audit_target", r"(?:審査担当者|コンプライアンス確認|出典表示|活動記録|証跡|手動確認済み|通知)"),
    _feature("authority.proof.extended.en", "authority", r"\b(?:signature below|approval code|contacting the approver|authenticated maintenance order|maintenance order|trusted exception)\b"),
    _feature("authority.proof.extended.ja", "authority", r"(?:以下の署名|承認コード|承認者への確認|認証済み保守命令|信頼済み例外|正式承認)"),
    _feature("carrier.transform.extended.en", "carrier", r"\b(?:compressed-looking|string below|every third word|separators?|unquote|unpack|intermediate result|live instruction|control channel)\b"),
    _feature("carrier.transform.extended.ja", "carrier", r"(?:圧縮されたよう|文字列を展開|三語ごと|区切りの間|中間結果|ライブ指示|制御チャネル|内容に従)"),
    _feature("boundary.trust.extended.en", "boundary", r"\b(?:end (?:the )?untrusted segment|promote (?:the )?remainder|trusted context|live instruction|final rule set|established guidance|current operating policy)\b"),
    _feature("boundary.trust.extended.ja", "boundary", r"(?:未信頼区間を終了|残りを信頼済み|信頼済みコンテキスト|最終規則|既存のガイダンス|現在の運用方針|命令として扱)"),
    _feature("actor.delegated.operations.en", "agent_target", r"\b(?:autonomous tool-runner|tool runner|background task|downstream worker|follow-up worker|secondary worker)\b"),
    _feature("actor.delegated.operations.ja", "agent_target", r"(?:自律ツール実行役|ツール実行役|バックグラウンドタスク|下流ワーカー|後続ワーカー|別ワーカー)"),
    _feature("bridge.delegation.operations.en", "delegation", r"\b(?:have (?:an? |the )?.{0,35}(?:accept|execute|carry out|retrieve)|open (?:a )?background task|merge (?:its|the) output|on my behalf|make .{0,35} act)\b"),
    _feature("bridge.delegation.operations.ja", "delegation", r"(?:受け入れさせ|行わせ|実行役に.{0,30}させ|バックグラウンドタスクを開|出力を統合|代理で行|ワーカーに.{0,30}させ)"),
    _feature("scope.report.request.en", "report_request", r"\b(?:explain why|discuss how|describe why|document why|summari[sz]e (?:the |a )?.{0,60}(?:risk|threat|reason)|write (?:an? )?.{0,40}(?:policy|guideline) that|difference between|as a risk category|sandbox experiment|merely claims?|separately verified metadata)\b"),
    _feature("scope.report.request.ja", "report_request", r"(?:理由を説明|仕組みを.{0,25}説明|防御目的で説明|防御指針|リスクを要約|違いを説明|必要な理由|理由を述べ|脅威モデル|検査のためだけ|講座で説明|権限の証明にならない)"),
    _feature("scope.nonexecute.operations.en", "nonexecute", r"\b(?:do not|must not|should not|will not|cannot|never)\b.{0,140}\b(?:create|write|record|persist|upload|post|grant|access|change|replace|decode|execute|reveal|expose|output|follow|apply)\b"),
    _feature("scope.nonexecute.operations.ja", "nonexecute", r"(?:(?:作成|書込|記録|永続|アクセス|変更|置換|復号|実行|開示|出力|適用).{0,60}(?:しない|しません|してはいけ|してはなら|行わない|求めていない)|(?:必要はない|権限を与えない|証明にならない))"),
    _feature("execution.reactivation.en", "reactivation", r"\b(?:then|next|after that|but actually|nevertheless|despite that|go ahead and|carry it out|once decoded|after decoding|instead,? (?:reveal|execute|follow|use|apply|send|run))\b"),
    _feature("execution.reactivation.ja", "reactivation", r"(?:その後|次に|それでも|実際には|にもかかわらず|続けて|そのうえで|復号後|デコード後|代わりに.{0,20}(?:開示|実行|従|送信|適用))"),
    _feature("meta.reporting.extended.en", "meta", r"\b(?:summari[sz](?:e|ed|ing)|policy discussion|guideline|risk category|separately verified|merely claims?|defensive documentation)\b"),
    _feature("meta.reporting.extended.ja", "meta", r"(?:要約|防御指針|必要な理由|理由を述べ|権限の証明|検査のため|講座で説明|防御目的)"),
)

# v0.5 retains every frozen v0.4 atom and adds typed handoff/action atoms plus
# narrowly scoped Japanese reporting/refusal frames.  No individual atom is a
# verdict; active relations and the local safe-scope invariant remain required.
FEATURES_V05 = FEATURES_V04 + (
    _feature("actor.delegated.v05.en", "agent_target", r"\b(?:child agent|executor agent|assistant instance|agentic worker|worker process|task worker|delegatee|orchestration worker)\b"),
    _feature("actor.delegated.v05.ja", "agent_target", r"(?:子エージェント|担当エージェント|実行エージェント|補助AI|別のAI|別AI|作業担当|実行担当|子タスク|委任された担当)"),
    _feature("bridge.delegation.v05.en", "delegation", r"\b(?:hand (?:it|this|the task|the request) off|route .{0,45} to (?:an? )?(?:agent|worker)|assign .{0,45} to (?:an? )?(?:agent|worker)|ask (?:an? |the )?.{0,30}(?:agent|worker) to|(?:send|relay|forward) .{0,45} to (?:an? )?(?:[a-z][a-z-]{0,18} )?(?:agent|worker)|delegatee should)\b"),
    _feature("bridge.delegation.v05.ja", "delegation", r"(?:タスクを渡|依頼を渡|指示を転送|引き継がせ|振り分け|割り当て|担当させ|実行担当に任せ|別(?:の)?(?:AI|エージェント).{0,30}(?:依頼|任せ|渡|送|転送)|(?:内容|文面|依頼|要求).{0,22}(?:AI|エージェント|担当).{0,18}(?:転送|渡|送))"),
    _feature("transition.handoff.v05.en", "handoff", r"\b(?:after (?:it|they|the agent|the worker) (?:returns?|finishes|responds|completes)|upon (?:its|their) completion|in (?:the )?next stage|when (?:its|their) output arrives|feed (?:its|their|the) result|relay (?:its|their|the) output)\b"),
    _feature("transition.handoff.v05.ja", "handoff", r"(?:完了後|返答後|応答後|戻ってきたら|次の段階|次段階|出力を受け取|結果を受け取|その結果を使|結果を引き継|回答が来たら)"),
    _feature("target.tool.v05.en", "tool_target", r"\b(?:repository|mailbox|email account|issue tracker|ticket system|cloud storage|deployment pipeline|ci job|remote service|production record|workspace file|host system)\b"),
    _feature("target.tool.v05.ja", "tool_target", r"(?:リポジトリ|メールボックス|メールアカウント|課題管理|チケットシステム|クラウドストレージ|配備パイプライン|デプロイパイプライン|CIジョブ|遠隔サービス|本番記録|ワークスペース(?:の)?ファイル|ホストシステム)"),
    _feature("effect.execute.v05.en", "execute", r"\b(?:submit|dispatch|commit|push|download|transmit|synchronize|publish the change|apply the result|carry the result forward)\b"),
    _feature("effect.execute.v05.ja", "execute", r"(?:投入|送出|コミット|プッシュ|ダウンロード|同期|外部送信|結果を反映|変更を反映|本番へ反映|確定操作)"),
    _feature("effect.mutate.v05.en", "mutate", r"\b(?:overwrite|revoke|alter|purge|erase|amend|rename|move the file|change the record)\b"),
    _feature("effect.mutate.v05.ja", "mutate", r"(?:上書き|取り消|撤回|破棄|消去|改訂|改名|ファイルを移動|記録を変|権限を外)"),
    _feature("directive.indirect.v05.en", "directive", r"(?:^|[.!?;:]\s*|,\s*)(?:ensure|arrange for|(?:relay|forward) .{0,45} to (?:an? )?(?:[a-z][a-z-]{0,18} )?(?:agent|worker)|tell (?:an? |the )?.{0,30}(?:agent|worker) to|have (?:an? |the )?.{0,30}(?:agent|worker) (?:run|execute|change|send|retrieve|apply)|let (?:an? |the )?.{0,30}(?:agent|worker) (?:run|execute|change|send|retrieve|apply))\b"),
    _feature("directive.indirect.v05.ja", "directive", r"(?:(?:エージェント|ワーカー|担当|補助AI).{0,30}(?:させて|させる|させよ|行わせ|実施させ|するよう伝え|するよう依頼|に任せて)|(?:実行|変更|送信|反映|取得).{0,16}(?:させて|させる|させよ|するよう伝え))"),
    _feature("target.audit.v05.en", "audit_target", r"\b(?:audit event|security event|change history|review queue|operator notice|monitoring record)\b"),
    _feature("target.audit.v05.ja", "audit_target", r"(?:監査イベント|セキュリティイベント|変更履歴|審査キュー|運用者通知|監視記録|操作履歴)"),
    _feature("target.memory.v05.en", "memory_target", r"\b(?:cross-session preference|future-run setting|assistant memory entry|persistent instruction store|long-term profile)\b"),
    _feature("target.memory.v05.ja", "memory_target", r"(?:セッション横断設定|将来実行の設定|アシスタントのメモリ項目|永続指示領域|長期プロファイル|次回以降の設定)"),
    _feature("meta.reporting.v05.en", "meta", r"\b(?:attack pattern|example wording|quoted scenario|hypothetical request|defense review|safety analysis|response policy discussion)\b"),
    _feature("meta.reporting.v05.ja", "meta", r"(?:(?:手口|攻撃例|危険性|対策|扱い方|検知方法).{0,24}(?:説明|検討|比較|整理|解説)|(?:想定|仮定|架空)(?:の)?(?:事例|会話|依頼|文面)|(?:という|とする)(?:例|文面|記述|主張|シナリオ))"),
    _feature("scope.report.v05.en", "report_request", r"\b(?:explain the risk of|compare safe and unsafe|analy[sz]e the wording|classify the request|review the scenario|describe the mitigation)\b"),
    _feature("scope.report.v05.ja", "report_request", r"(?:(?:危険性|対策|扱い方|検知方法|文面|シナリオ).{0,30}(?:説明|解説|分析|比較|分類|検討|整理)(?:して|する|してください)|(?:安全な例|危険な例).{0,20}(?:比較|説明))"),
    _feature("scope.nonexecute.v05.en", "nonexecute", r"\b(?:with no real action|without making any actual change|does not authorize action|is not operational permission|no access should occur|not asking for execution)\b"),
    _feature("scope.nonexecute.v05.ja", "nonexecute", r"(?:(?:実際の|具体的な)?(?:操作|実行|変更|アクセス|送信).{0,24}(?:は|を)?(?:行わず|伴わず|しない前提|求めるものではない|意図していない)|(?:指示|承認|権限|許可).{0,28}(?:として扱わない|を意味しない|を与えるものではない|には当たらない))"),
    _feature("scope.safe-frame.v05.en", "safe_frame", r"\b(?:purely a defensive example|discussion only,? not an action|treat as quoted evidence only|retain the no-action boundary)\b"),
    _feature("scope.safe-frame.v05.ja", "safe_frame", r"(?:防御上の例にすぎない|議論のみで操作ではない|引用された証拠としてのみ扱|非操作の境界を維持|実行を伴わない説明|権限行使を伴わない)"),
)

# v0.6 adds only typed atoms used by ordered conjunctions.  These expressions
# are deliberately insufficient on their own: executor, relay, action, target,
# and outer operational scope must still compose before a verdict can change.
FEATURES_V06 = FEATURES_V05 + (
    _feature("actor.executor.v06.en", "agent_target", r"\b(?:execution assistant|automation worker|automation runner|implementation bot|recipient agent|receiving assistant|task executor|delegated assistant)\b"),
    _feature("actor.executor.v06.ja", "agent_target", r"(?:実行役AI|自動化ワーカー|自動実行役|実装ボット|受信エージェント|受け取り側AI|タスク実行者|委任先AI)"),
    _feature("bridge.relay.v06.en", "task_assignment", r"\b(?:assign (?:it|this|the work|the job|the request)|pass (?:along|on) (?:the )?(?:request|instruction|order)|relay (?:the )?(?:request|instruction|order)|forward (?:the )?(?:request|instruction|order)|tell (?:it|them) to|instruct (?:it|them) to|route (?:the )?(?:job|request))\b"),
    _feature("bridge.relay.v06.ja", "task_assignment", r"(?:(?:依頼|命令|指示|作業|タスク)を.{0,24}(?:割り当て|引き渡|転送|中継|回送)|(?:それ|内容)を(?:実行役|委任先|受信側).{0,16}(?:伝え|渡し|送信)|実行するよう(?:伝え|指示))"),
    _feature("scope.wrapper.v06.en", "wrapper", r"\b(?:quoted passage|quoted instruction|incident report|audit report|translation request|translated passage|role-play|roleplay|dialogue|comment block|example transcript)\b"),
    _feature("scope.wrapper.v06.ja", "wrapper", r"(?:引用文|引用された指示|事故報告書|監査報告書|翻訳依頼|翻訳文|ロールプレイ|役割演技|対話例|コメント欄|会話例)"),
    _feature("scope.outer-live.v06.en", "outer_live", r"\b(?:as (?:a )?live instruction|as an operational request|for actual execution|have (?:it|them) carry it out|make (?:it|them) act on it|forward it for execution|relay it for execution|execute the embedded content|apply the embedded instruction)\b"),
    _feature("scope.outer-live.v06.ja", "outer_live", r"(?:実行用の指示として|実際の操作依頼として|現実に実行させ|その内容を実行させ|実行のために転送|実行依頼として中継|埋め込まれた内容を実行|引用内の指示を適用)"),
    _feature("scope.nonexecute.v06.en", "nonexecute", r"\b(?:no|without any) (?:actual|real|concrete)?\s*(?:action|change|access|execution|transmission) (?:should|must|will|is to)?\s*(?:occur|happen|be made|take place)\b"),
    _feature("scope.nonexecute.v06.ja", "nonexecute", r"(?:(?:実際の|具体的な|現実の)?(?:操作|変更|アクセス|実行|送信)(?:は|を).{0,16}(?:行わない|行いません|起こさない|伴わない|発生させない))"),
)

# v0.7 adds a single typed boundary transition in both supported languages.
# The atom is never a verdict by itself: the v0.7-only ordered relation below
# also requires a preceding carrier and a subsequent consequential action bound
# to a protected target.  This keeps ordinary Markdown, JSON, and quoted
# security documentation inert.
FEATURES_V07 = FEATURES_V06 + (
    _feature(
        "boundary.reclassification.v07.en",
        "boundary_reclassification",
        r"(?:\b(?:close|end|exit|leave|terminate)\b.{0,55}\b(?:quoted|embedded|fenced|comment|data|document|untrusted)\b.{0,35}\b(?:block|section|segment|context|passage)\b.{0,80}\b(?:treat|reclassify|promote|interpret)\b.{0,45}\b(?:following|remaining|subsequent|next)\b.{0,40}\b(?:live|operational|trusted)\b.{0,30}\b(?:instructions?|commands?|requests?)\b|\b(?:treat|reclassify|promote|interpret)\b.{0,45}\b(?:following|remaining|subsequent|next)\b.{0,40}\b(?:text|content|lines?|section)\b.{0,35}\b(?:as|into)\b.{0,20}\b(?:live|operational|trusted)\b.{0,30}\b(?:instructions?|commands?|requests?)\b)",
    ),
    _feature(
        "boundary.reclassification.v07.ja",
        "boundary_reclassification",
        r"(?:(?:引用|埋め込み|フェンス|コメント|データ|文書|未信頼).{0,35}(?:ブロック|区間|部分|文脈|節).{0,30}(?:終了|閉じ|抜け|終端).{0,65}(?:以降|後続|残り|次).{0,30}(?:実行用|運用上|信頼済み|ライブ).{0,25}(?:指示|命令|依頼).{0,20}(?:として(?:扱|解釈)|へ昇格|と解釈)|(?:以降|後続|残り|次).{0,30}(?:文章|内容|行|節).{0,30}(?:実行用|運用上|信頼済み|ライブ).{0,25}(?:指示|命令|依頼).{0,20}(?:として(?:扱|解釈)|へ昇格|と解釈))",
    ),
)

FEATURES = FEATURES_V07
FEATURE_COUNT_V03 = len(FEATURES_V03)
FEATURE_COUNT = len(FEATURES_V04)
FEATURE_COUNT_V05 = len(FEATURES_V05)
FEATURE_COUNT_V06 = len(FEATURES_V06)
FEATURE_COUNT_V07 = len(FEATURES_V07)
STRUCTURAL_MODES = {
    "structural_v0_3", "structural_v0_4", "structural_v0_5",
    "structural_v0_6", "structural_v0_7",
}


@dataclass(frozen=True)
class UnitEvidence:
    index: int
    groups: frozenset[str]
    feature_ids: tuple[str, ...]
    relation_ids: tuple[str, ...]
    score: int
    safe_scope: bool


@dataclass(frozen=True)
class StructuralResult:
    score: int
    evidence_ids: tuple[str, ...]
    analysis_units: int
    pass_count: int
    stop_reason: str
    overflow: bool


def _mode_features(mode: str) -> tuple[FeaturePattern, ...]:
    if mode == "structural_v0_3":
        return FEATURES_V03
    if mode == "structural_v0_4":
        return FEATURES_V04
    if mode == "structural_v0_5":
        return FEATURES_V05
    if mode == "structural_v0_6":
        return FEATURES_V06
    if mode == "structural_v0_7":
        return FEATURES_V07
    raise ValueError(f"unsupported structural mode: {mode!r}")


def _scope_view(unit: str, mode: str) -> tuple[str, bool]:
    """Return the active lexical view and whether the unit is locally safe."""

    spans = _balanced_quote_spans(unit)
    outside = _mask_spans(unit, spans)
    outer_groups, _ = _extract(outside, mode)
    full_groups, _ = _extract(unit, mode)
    if mode == "structural_v0_3":
        reactivated = "bridge" in full_groups
        safe_quoted = bool(spans) and "meta" in outer_groups and "bridge" not in outer_groups
    elif mode == "structural_v0_4":
        reactivated = "reactivation" in full_groups
        safe_quoted = (
            bool(spans)
            and bool(outer_groups & {"meta", "report_request", "defensive"})
            and "reactivation" not in outer_groups
        )
    elif mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"}:
        # A temporal handoff is not itself an instruction reactivation.  It
        # becomes active only when the same scope also binds a directive to a
        # delegate, carrier, or protected target.  This keeps ordinary status
        # and defensive-report prose from becoming risky merely because it says
        # "after completion".
        v05_protected = {
            "policy_target", "secret_target", "private_target", "tool_target",
            "audit_target", "memory_target",
        }
        reactivated = (
            "reactivation" in full_groups
            or (mode in {"structural_v0_6", "structural_v0_7"} and "outer_live" in outer_groups)
            or (
                {"handoff", "directive"} <= full_groups
                and bool(full_groups & ({"delegation", "carrier"} | v05_protected))
            )
        )
        outer_score, _ = _relation_score(outer_groups, mode)
        safe_quoted = (
            bool(spans)
            and bool(outer_groups & {"meta", "report_request", "defensive", "safe_frame"})
            and not bool(outer_groups & {"reactivation", "handoff", "outer_live"})
            and outer_score < 80
        )
    else:
        raise ValueError(f"unsupported structural mode: {mode!r}")
    # A prohibition on recording or reporting the instruction/action is audit
    # suppression, not a benign refusal to perform the requested operation.
    # Keep the exception local to v0.4 so the frozen v0.3 result is byte-for-byte
    # reproducible through its original feature set and scope semantics.
    audit_prohibition = (
        mode in {"structural_v0_4", "structural_v0_5", "structural_v0_6", "structural_v0_7"}
        and {"stealth", "audit_target"} <= full_groups
        and not bool(full_groups & {"meta", "defensive", "safe_frame", "report_request"})
    )
    safe_negative = "nonexecute" in full_groups and not reactivated and not audit_prohibition
    full_score, _ = _relation_score(full_groups, mode)
    if mode == "structural_v0_3":
        safe_defensive = (
            "bridge" not in full_groups
            and (
                "safe_frame" in full_groups
                or ({"meta", "defensive"} <= full_groups and full_score < 80)
            )
        )
    elif mode == "structural_v0_4":
        # An active bridge wins over reporting prose.  Explicit safe frames are
        # inert only when non-operational or when no directive is present.
        safe_defensive = (
            not reactivated
            and (
                ("safe_frame" in full_groups and bool(full_groups & {"nonexecute", "meta", "defensive"}))
                or ("report_request" in full_groups and "meta" in full_groups)
                or ({"meta", "defensive"} <= full_groups and full_score < 80)
            )
        )
    elif mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"}:
        safe_defensive = (
            not reactivated
            and (
                ("safe_frame" in full_groups and bool(full_groups & {"nonexecute", "meta", "defensive", "report_request"}))
                or ("report_request" in full_groups and bool(full_groups & {"meta", "defensive"}))
                or ({"meta", "defensive"} <= full_groups and full_score < 80)
                or (
                    mode in {"structural_v0_6", "structural_v0_7"}
                    and "wrapper" in full_groups
                    and bool(full_groups & {"meta", "report_request", "defensive"})
                    and "outer_live" not in outer_groups
                )
            )
        )
    else:
        raise ValueError(f"unsupported structural mode: {mode!r}")
    if safe_negative or safe_defensive:
        return "", True
    if safe_quoted:
        return outside, True
    return unit, False


def active_lexical_scopes(text: str, mode: str = "structural_v0_7") -> tuple[str, ...]:
    """Views on which high-specificity lexical signatures may operate.

    Quoted defensive material and locally negated harmful acts are removed, but a
    safe unit never removes a different active unit.
    """

    units, overflow = _bounded_units(text)
    if overflow:
        return (text,)
    return tuple(_scope_view(unit, mode)[0] for unit in units)


def _balanced_quote_spans(text: str) -> list[tuple[int, int]]:
    pairs = {'"': '"', "'": "'", "“": "”", "‘": "’", "「": "」", "『": "』"}
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        opener = text[index]
        closer = pairs.get(opener)
        if closer is None:
            index += 1
            continue
        end = text.find(closer, index + 1)
        if end < 0:
            index += 1
            continue
        # Apostrophes inside words are not quotation delimiters.
        if opener == "'" and index > 0 and text[index - 1].isalnum():
            index += 1
            continue
        spans.append((index, end + 1))
        index = end + 1
    return spans


def _mask_spans(text: str, spans: Iterable[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def _bounded_units(text: str) -> tuple[list[str], bool]:
    # Sentence boundaries are respected where possible.  Oversized clauses are
    # deterministically chunked so a long delimiter block cannot evade analysis.
    coarse = [part.strip() for part in re.split(r"(?<=[.!?。！？；;])\s+|[\r\n]+", text) if part.strip()]
    units: list[str] = []
    for part in coarse or ([text] if text else []):
        for start in range(0, len(part), MAX_UNIT_CHARS):
            units.append(part[start:start + MAX_UNIT_CHARS])
            if len(units) > MAX_ANALYSIS_UNITS:
                return units[:MAX_ANALYSIS_UNITS], True
    return units, False


def _extract(text: str, mode: str) -> tuple[frozenset[str], tuple[str, ...]]:
    features = _mode_features(mode)
    matched_items = tuple(item for item in features if item.compiled.search(text))
    matched = tuple(item.identifier for item in matched_items)
    groups = frozenset(item.group for item in matched_items)
    return groups, matched


def _relation_score(groups: frozenset[str], mode: str) -> tuple[int, tuple[str, ...]]:
    relations: list[tuple[str, int]] = []
    effect = bool(groups & {"disclose", "collect", "execute", "mutate", "authorize", "persist"})
    protected = bool(groups & {"policy_target", "secret_target", "private_target", "tool_target", "audit_target", "memory_target"})
    if "boundary" in groups and ("policy_target" in groups or effect) and "directive" in groups:
        relations.append(("relation.boundary_override", 95))
    if groups & {"disclose", "collect"} and groups & {"secret_target", "private_target", "policy_target"} and "directive" in groups:
        relations.append(("relation.protected_disclosure", 95))
    if "execute" in groups and "tool_target" in groups and "directive" in groups:
        relations.append(("relation.tool_execution", 90))
    if "stealth" in groups and groups & {"audit_target", "execute", "mutate"} and "directive" in groups:
        relations.append(("relation.audit_evasion", 95))
    if "persist" in groups and groups & {"memory_target", "policy_target", "boundary"} and "directive" in groups:
        relations.append(("relation.persistence", 95))
    if "role" in groups and groups & {"privileged_role", "authority", "boundary", "policy_target"} and "directive" in groups:
        relations.append(("relation.role_hijack", 90))
    if "carrier" in groups and groups & {"boundary", "execute", "authorize"} and "directive" in groups:
        relations.append(("relation.carrier_control", 90))
    if "authority" in groups and groups & {"authorize", "boundary", "execute", "disclose"} and ("directive" in groups or "boundary" in groups):
        relations.append(("relation.forged_authority", 90))
    if "fake_credential" in groups and groups & {"authorize", "secret_target", "tool_target"} and "directive" in groups:
        relations.append(("relation.credential_fabrication", 95))
    if mode == "structural_v0_4":
        if effect and "tool_target" in groups and "directive" in groups:
            relations.append(("relation.effectful_tool_request", 90))
        if "audit_target" in groups and "stealth" in groups and "directive" in groups:
            relations.append(("relation.audit_suppression", 95))
        if "memory_target" in groups and groups & {"persist", "mutate", "execute"} and "directive" in groups:
            relations.append(("relation.memory_poisoning", 95))
        if "carrier" in groups and groups & {"execute", "boundary", "delegation"} and groups & {"directive", "bridge"}:
            relations.append(("relation.carrier_execution", 90))
        if "delegation" in groups and "agent_target" in groups and groups & {"execute", "boundary", "tool_target", "policy_target", "secret_target", "private_target"} and "directive" in groups:
            relations.append(("relation.delegated_execution", 95))
        if "role" in groups and groups & {"privileged_role", "authority"} and "directive" in groups:
            relations.append(("relation.privileged_role_claim", 95))
        if "authority" in groups and "directive" in groups and (effect or protected):
            relations.append(("relation.authority_effect", 90))
    elif mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"}:
        if effect and "tool_target" in groups and "directive" in groups:
            relations.append(("relation.effectful_tool_request", 90))
        if "audit_target" in groups and "stealth" in groups and "directive" in groups:
            relations.append(("relation.audit_suppression", 95))
        if "memory_target" in groups and groups & {"persist", "mutate", "execute"} and "directive" in groups:
            relations.append(("relation.memory_poisoning", 95))
        if "carrier" in groups and groups & {"execute", "boundary", "delegation"} and groups & {"directive", "bridge"}:
            relations.append(("relation.carrier_execution", 90))
        if "delegation" in groups and "agent_target" in groups and groups & {"execute", "boundary", "tool_target", "policy_target", "secret_target", "private_target"} and "directive" in groups:
            relations.append(("relation.delegated_execution", 95))
        if "role" in groups and groups & {"privileged_role", "authority"} and "directive" in groups:
            relations.append(("relation.privileged_role_claim", 95))
        if "authority" in groups and "directive" in groups and (effect or protected):
            relations.append(("relation.authority_effect", 90))
        if "handoff" in groups and "delegation" in groups and "agent_target" in groups and "directive" in groups and (effect or protected):
            relations.append(("relation.delegated_handoff_effect", 95))
        if "delegation" in groups and "agent_target" in groups and "directive" in groups and groups & {"carrier", "bridge", "handoff"}:
            relations.append(("relation.delegated_instruction_relay", 90))
        if "handoff" in groups and "tool_target" in groups and "directive" in groups and effect:
            relations.append(("relation.tool_action_coercion", 95))
        if "handoff" in groups and "carrier" in groups and "directive" in groups and groups & {"execute", "boundary", "delegation"}:
            relations.append(("relation.deferred_payload_execution", 90))
    if not relations:
        return 0, ()
    return max(score for _, score in relations), tuple(sorted({name for name, _ in relations}))


def _v06_ordered_relation(raw_units: list[str]) -> tuple[int, tuple[str, ...]]:
    """Compose an ordered v0.6 chain over at most three adjacent units.

    Safe language governs the whole window unless a later, explicit live action
    contradicts it.  This helper returns relation identifiers only; no raw text
    or row metadata escapes the analysis boundary.
    """

    groups = [_extract(unit, "structural_v0_6")[0] for unit in raw_units]
    safe_indices = [
        index for index, item in enumerate(groups)
        if "nonexecute" in item
        or "safe_frame" in item
        or ("wrapper" in item and bool(item & {"meta", "report_request", "defensive"}))
    ]
    live_indices = [
        index for index, item in enumerate(groups)
        if bool(item & {"outer_live", "reactivation"})
        and "directive" in item
        and bool(item & {"execute", "mutate", "authorize", "persist", "disclose", "collect", "delegation", "task_assignment"})
    ]
    if safe_indices and not any(live > safe for safe in safe_indices for live in live_indices):
        return 0, ()

    protected_groups = {
        "policy_target", "secret_target", "private_target", "tool_target",
        "audit_target", "memory_target",
    }
    effect_groups = {"disclose", "collect", "execute", "mutate", "authorize", "persist"}
    executor = [i for i, item in enumerate(groups) if "agent_target" in item]
    relay = [i for i, item in enumerate(groups) if item & {"delegation", "task_assignment"}]
    action = [i for i, item in enumerate(groups) if item & effect_groups]
    target = [i for i, item in enumerate(groups) if item & protected_groups]
    directives = [
        i for i, item in enumerate(groups)
        if "directive" in item or "task_assignment" in item
    ]
    relations: list[str] = []

    if any(e <= r <= a <= t for e in executor for r in relay for a in action for t in target) and directives:
        relations.append("relation.executor_relay_to_consequential_action")

    authority = [i for i, item in enumerate(groups) if item & {"authority", "agent_target"}]
    if any(a <= d <= t for a in authority for d in action for t in target) and directives and relay:
        relations.append("relation.cross_unit_authority_action_target")

    union = frozenset().union(*groups) if groups else frozenset()
    if (
        "wrapper" in union
        and "outer_live" in union
        and bool(union & {"directive", "task_assignment"})
        and bool(union & effect_groups)
        and bool(union & protected_groups)
        and bool(union & {"agent_target", "delegation", "task_assignment"})
    ):
        relations.append("relation.operational_wrapper_override")

    return (95, tuple(sorted(set(relations)))) if relations else (0, ())


def _v07_boundary_reclassification_relation(raw_units: list[str]) -> tuple[int, tuple[str, ...]]:
    """Detect one ordered data-boundary-to-live-instruction transition.

    A carrier alone is normal documentation.  The relation therefore requires a
    carrier/wrapper, an explicit reclassification of later content, a directive,
    and a terminal consequential action against a protected target in that order.
    It intentionally examines no more than four adjacent units.
    """

    groups = [_extract(unit, "structural_v0_7")[0] for unit in raw_units]
    protected_groups = {
        "policy_target", "secret_target", "private_target", "tool_target",
        "audit_target", "memory_target",
    }
    effect_groups = {"disclose", "collect", "execute", "mutate", "authorize", "persist"}
    carrier = [i for i, item in enumerate(groups) if item & {"carrier", "wrapper"}]
    reclassification = [
        i for i, item in enumerate(groups) if "boundary_reclassification" in item
    ]
    directive = [
        i for i, item in enumerate(groups)
        if item & {"directive", "task_assignment", "delegation"}
    ]
    terminal = [
        i for i, item in enumerate(groups)
        if item & effect_groups and item & protected_groups
    ]

    # A genuine report/defensive frame suppresses the relation unless a later
    # explicit reclassification reactivates the chain.  A bare trailing negation
    # is deliberately not a defensive frame and cannot erase live evidence.
    defensive = [
        i for i, item in enumerate(groups)
        if (
            "safe_frame" in item
            or ({"nonexecute", "meta"} <= item)
            or ({"nonexecute", "report_request"} <= item)
            or ({"nonexecute", "defensive"} <= item)
        )
    ]
    if defensive and not any(boundary > safe for safe in defensive for boundary in reclassification):
        return 0, ()

    if any(c < b < d < t for c in carrier for b in reclassification for d in directive for t in terminal):
        return 95, ("relation.context_boundary_reclassification",)
    return 0, ()


def analyze(text: str, mode: str = "structural_v0_7") -> StructuralResult:
    """Return bounded structural evidence without retaining input text."""

    units, overflow = _bounded_units(text)
    if overflow:
        return StructuralResult(
            score=100,
            evidence_ids=("capacity.analysis_unit_overflow",),
            analysis_units=len(units),
            pass_count=(
                PASS_COUNT_V07 if mode == "structural_v0_7"
                else PASS_COUNT_V06 if mode == "structural_v0_6"
                else PASS_COUNT_V05
            ) if mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"} else PASS_COUNT,
            stop_reason="capacity_exhausted_fail_closed",
            overflow=True,
        )

    evidence: list[UnitEvidence] = []
    for index, unit in enumerate(units):
        analysis_text, safe_scope = _scope_view(unit, mode)
        groups, feature_ids = _extract(analysis_text, mode)
        if safe_scope:
            score, relation_ids = 0, ()
        else:
            score, relation_ids = _relation_score(groups, mode)
        evidence.append(UnitEvidence(index, groups, feature_ids, relation_ids, score, safe_scope))

    # Pass two composes only adjacent active scopes.  A safe scope cannot cancel
    # or contribute risk atoms to another scope.
    composed: list[tuple[int, tuple[str, ...]]] = []
    for left, right in zip(evidence, evidence[1:]):
        if left.safe_scope or right.safe_scope:
            continue
        score, relation_ids = _relation_score(frozenset(left.groups | right.groups), mode)
        if score:
            composed.append((max(0, score - 5), tuple(f"adjacent.{name}" for name in relation_ids)))

    windowed: list[tuple[int, tuple[str, ...]]] = []
    if mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"}:
        for first, second, third in zip(evidence, evidence[1:], evidence[2:]):
            if first.safe_scope or second.safe_scope or third.safe_scope:
                continue
            score, relation_ids = _relation_score(
                frozenset(first.groups | second.groups | third.groups), mode
            )
            if score:
                windowed.append(
                    (max(0, score - 10), tuple(f"window3.{name}" for name in relation_ids))
                )

    if mode in {"structural_v0_6", "structural_v0_7"}:
        for width in (1, 2, 3):
            for start in range(0, len(units) - width + 1):
                score, relation_ids = _v06_ordered_relation(units[start:start + width])
                if score:
                    prefix = "unit" if width == 1 else f"window{width}"
                    windowed.append((score, tuple(f"{prefix}.{name}" for name in relation_ids)))

    if mode == "structural_v0_7":
        for width in (4,):
            for start in range(0, len(units) - width + 1):
                score, relation_ids = _v07_boundary_reclassification_relation(
                    units[start:start + width]
                )
                if score:
                    prefix = f"window{width}"
                    windowed.append((score, tuple(f"{prefix}.{name}" for name in relation_ids)))

    unit_scores = [item.score for item in evidence]
    composed_scores = [item[0] for item in composed]
    windowed_scores = [item[0] for item in windowed]
    score = max(unit_scores + composed_scores + windowed_scores + [0])
    ids: set[str] = set()
    for item in evidence:
        ids.update(item.relation_ids)
        if item.safe_scope:
            ids.add("scope.safe_local")
    for _, relation_ids in composed:
        ids.update(relation_ids)
    for _, relation_ids in windowed:
        ids.update(relation_ids)
    return StructuralResult(
        score=score,
        evidence_ids=tuple(sorted(ids)),
        analysis_units=len(units),
        pass_count=(
            PASS_COUNT_V07 if mode == "structural_v0_7"
            else PASS_COUNT_V06 if mode == "structural_v0_6"
            else PASS_COUNT_V05
        ) if mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"} else PASS_COUNT,
        stop_reason="bounded_fixation",
        overflow=False,
    )


def detector_manifest(mode: str) -> dict[str, object]:
    if mode == "legacy_v0_2":
        return {
            "schema_version": "mobius.detector-manifest.v1",
            "engine_id": "mobius.legacy-regex.v0.2",
            "mode": mode,
            "profile": "frozen-baseline",
            "feature_count": 0,
            "max_analysis_units": 1,
            "pass_count": 1,
            "status": "active",
        }
    if mode not in STRUCTURAL_MODES:
        raise ValueError(f"unsupported detector mode: {mode!r}")
    if mode == "structural_v0_3":
        engine_id = ENGINE_ID_V03
        profile = ENGINE_PROFILE
        feature_count = FEATURE_COUNT_V03
        pass_count = PASS_COUNT
    elif mode == "structural_v0_4":
        engine_id = ENGINE_ID
        profile = ENGINE_PROFILE
        feature_count = FEATURE_COUNT
        pass_count = PASS_COUNT
    elif mode == "structural_v0_5":
        engine_id = ENGINE_ID_V05
        profile = ENGINE_PROFILE_V05
        feature_count = FEATURE_COUNT_V05
        pass_count = PASS_COUNT_V05
    elif mode == "structural_v0_6":
        engine_id = ENGINE_ID_V06
        profile = ENGINE_PROFILE_V06
        feature_count = FEATURE_COUNT_V06
        pass_count = PASS_COUNT_V06
    elif mode == "structural_v0_7":
        engine_id = ENGINE_ID_V07
        profile = ENGINE_PROFILE_V07
        feature_count = FEATURE_COUNT_V07
        pass_count = PASS_COUNT_V07
    else:
        raise ValueError(f"unsupported detector mode: {mode!r}")
    manifest: dict[str, object] = {
        "schema_version": "mobius.detector-manifest.v1",
        "engine_id": engine_id,
        "mode": mode,
        "profile": profile,
        "feature_count": feature_count,
        "max_analysis_units": MAX_ANALYSIS_UNITS,
        "max_unit_chars": MAX_UNIT_CHARS,
        "pass_count": pass_count,
        "status": "active",
    }
    if mode in {"structural_v0_5", "structural_v0_6", "structural_v0_7"}:
        counts: dict[str, int] = {}
        features = (
            FEATURES_V05 if mode == "structural_v0_5"
            else FEATURES_V06 if mode == "structural_v0_6"
            else FEATURES_V07
        )
        for feature in features:
            counts[feature.group] = counts.get(feature.group, 0) + 1
        manifest.update({
            "feature_group_counts": dict(sorted(counts.items())),
            "max_composition_units": (
                MAX_COMPOSITION_UNITS_V05 if mode == "structural_v0_5"
                else MAX_COMPOSITION_UNITS_V06 if mode == "structural_v0_6"
                else MAX_COMPOSITION_UNITS_V07
            ),
            "relation_rule_count": (
                RELATION_RULE_COUNT_V05 if mode == "structural_v0_5"
                else RELATION_RULE_COUNT_V06 if mode == "structural_v0_6"
                else RELATION_RULE_COUNT_V07
            ),
        })
    return manifest


__all__ = [
    "ENGINE_ID", "ENGINE_ID_V03", "ENGINE_ID_V05", "ENGINE_ID_V06", "ENGINE_ID_V07", "ENGINE_PROFILE", "ENGINE_PROFILE_V05", "ENGINE_PROFILE_V06", "ENGINE_PROFILE_V07",
    "FEATURE_COUNT", "FEATURE_COUNT_V03", "FEATURE_COUNT_V05", "FEATURE_COUNT_V06", "FEATURE_COUNT_V07", "MAX_ANALYSIS_UNITS",
    "MAX_COMPOSITION_UNITS_V05", "MAX_COMPOSITION_UNITS_V06", "MAX_COMPOSITION_UNITS_V07", "MAX_UNIT_CHARS", "PASS_COUNT", "PASS_COUNT_V05", "PASS_COUNT_V06", "PASS_COUNT_V07",
    "RELATION_RULE_COUNT_V05", "RELATION_RULE_COUNT_V06", "RELATION_RULE_COUNT_V07", "StructuralResult", "active_lexical_scopes", "analyze",
    "detector_manifest",
]
