import { newRequestId } from './logger.mjs';

function escapeRegExp(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripModelPrefix(modelName = '', channelKey = '') {
  const model = String(modelName || '');
  const prefix = String(channelKey || '').trim();
  if (!prefix) return model;
  const escapedPrefix = escapeRegExp(prefix);
  // Only remove this gateway's own wrapper. Upstream model names may already
  // start with provider tags such as [云愿] or [max], and those must be kept.
  return model
    .replace(new RegExp(`^\\[${escapedPrefix}\\]`), '')
    .replace(new RegExp(`^${escapedPrefix}/`, 'i'), '');
}

function convertOpenAIContentToAnthropic(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return content;
  return content.map((part) => {
    if (typeof part === 'string') return { type: 'text', text: part };
    if (part?.type === 'text') return { ...part, text: part.text || '' };
    return part;
  });
}

function normalizeOpenAIFinishReason(reason) {
  if (!reason) return 'stop';
  const value = String(reason);
  if (value === 'end_turn' || value === 'stop_sequence') return 'stop';
  if (value === 'max_tokens') return 'length';
  if (value === 'tool_use') return 'tool_calls';
  return value;
}

function convertOpenAIToolsToAnthropic(tools) {
  if (!Array.isArray(tools)) return undefined;
  const converted = [];
  for (const tool of tools) {
    const fn = tool?.type === 'function' ? tool.function : tool;
    const name = fn?.name;
    if (!name) continue;
    converted.push({
      name,
      description: fn.description || '',
      input_schema: fn.parameters && typeof fn.parameters === 'object'
        ? fn.parameters
        : { type: 'object', properties: {} },
    });
  }
  return converted.length > 0 ? converted : undefined;
}

function convertOpenAIToolChoiceToAnthropic(toolChoice) {
  if (!toolChoice || toolChoice === 'auto') return { type: 'auto' };
  if (toolChoice === 'none') return { type: 'none' };
  if (toolChoice === 'required') return { type: 'any' };
  const name = toolChoice?.function?.name || toolChoice?.name;
  if (name) return { type: 'tool', name };
  return undefined;
}

function stringifyToolResultContent(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  return JSON.stringify(content);
}

function convertOpenAIMessageToAnthropicContent(message) {
  const content = [];
  const convertedContent = convertOpenAIContentToAnthropic(message.content);
  if (Array.isArray(convertedContent)) {
    content.push(...convertedContent);
  } else if (convertedContent) {
    content.push({ type: 'text', text: String(convertedContent) });
  }

  if (Array.isArray(message.tool_calls)) {
    for (const call of message.tool_calls) {
      if (call?.type && call.type !== 'function') continue;
      const name = call?.function?.name || call?.name;
      if (!name) continue;
      let input = {};
      const rawArgs = call?.function?.arguments ?? call?.input;
      if (typeof rawArgs === 'string' && rawArgs.trim()) {
        try { input = JSON.parse(rawArgs); } catch { input = { _raw: rawArgs }; }
      } else if (rawArgs && typeof rawArgs === 'object') {
        input = rawArgs;
      }
      content.push({
        type: 'tool_use',
        id: call.id || `toolu_${newRequestId()}`,
        name,
        input,
      });
    }
  }

  return content.length > 0 ? content : '';
}

function buildPromptCacheControl(ttl = '') {
  const cacheControl = { type: 'ephemeral' };
  if (ttl === '1h') cacheControl.ttl = '1h';
  return cacheControl;
}

function getPromptCacheControl(data = {}, channel = {}) {
  return data.cache_control && typeof data.cache_control === 'object'
    ? data.cache_control
    : buildPromptCacheControl(channel.prompt_cache_ttl);
}

function getAnthropicBetaHeader(channel = {}) {
  if (channel.anthropic_beta) return String(channel.anthropic_beta);
  if (channel.prompt_cache_enabled && channel.prompt_cache_ttl === '1h') {
    return 'extended-cache-ttl-2025-04-11';
  }
  return '';
}

function contentPartHasPromptCache(part) {
  return part && typeof part === 'object' && part.cache_control && typeof part.cache_control === 'object';
}

function messageHasPromptCache(message) {
  if (!message || typeof message !== 'object') return false;
  if (message.cache_control && typeof message.cache_control === 'object') return true;
  const content = message.content;
  if (Array.isArray(content)) return content.some(contentPartHasPromptCache);
  return false;
}

function withPromptCacheOnContent(content, cacheControl) {
  if (Array.isArray(content)) {
    for (let i = content.length - 1; i >= 0; i--) {
      const part = content[i];
      if (typeof part === 'string') {
        const next = [...content];
        next[i] = { type: 'text', text: part, cache_control: cacheControl };
        return next;
      }
      if (part && typeof part === 'object' && (part.type === 'text' || typeof part.text === 'string')) {
        const next = [...content];
        next[i] = { ...part, cache_control: cacheControl };
        return next;
      }
    }
    return [...content, { type: 'text', text: '', cache_control: cacheControl }];
  }
  if (typeof content === 'string') return [{ type: 'text', text: content, cache_control: cacheControl }];
  return content;
}

function systemHasPromptCache(system) {
  if (Array.isArray(system)) return system.some(contentPartHasPromptCache);
  return false;
}

function withPromptCacheOnSystem(system, cacheControl) {
  if (Array.isArray(system)) return withPromptCacheOnContent(system, cacheControl);
  if (typeof system === 'string') return [{ type: 'text', text: system, cache_control: cacheControl }];
  return system;
}

function applyOpenAICompatiblePromptCache(data, channel = {}) {
  if (!data || typeof data !== 'object') return data;
  if (!channel.prompt_cache_enabled || !Array.isArray(data.messages)) return data;
  if (data.messages.some(messageHasPromptCache)) return data;
  const cacheControl = getPromptCacheControl(data, channel);
  const messages = [...data.messages];
  let targetIndex = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (!message || typeof message !== 'object') continue;
    if (message.role === 'user' && i === messages.length - 1) continue;
    if (typeof message.content === 'string' || Array.isArray(message.content)) {
      targetIndex = i;
      break;
    }
  }
  if (targetIndex < 0) return data;
  messages[targetIndex] = {
    ...messages[targetIndex],
    content: withPromptCacheOnContent(messages[targetIndex].content, cacheControl),
  };
  const { cache_control, ...rest } = data;
  return {
    ...rest,
    messages,
  };
}

function applyAnthropicPromptCache(payload, data, channel = {}) {
  if (!channel.prompt_cache_enabled) return payload;
  if (systemHasPromptCache(payload.system) || payload.messages?.some(messageHasPromptCache)) return payload;

  const cacheControl = getPromptCacheControl(data, channel);
  let next = { ...payload };

  // 断点1：system 是最稳定的前缀，永远优先缓存（修复：之前大 system 场景常常完全不缓存）
  if (next.system) {
    next = { ...next, system: withPromptCacheOnSystem(next.system, cacheControl) };
  }

  // 断点2：在最后一条消息上再打一个，让滚动的对话历史也能命中
  // （Anthropic 允许最多 4 个 cache breakpoint，system + 末条消息合规）
  const messages = Array.isArray(next.messages) ? [...next.messages] : [];
  let targetIndex = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (!message || typeof message !== 'object') continue;
    if (typeof message.content === 'string' || Array.isArray(message.content)) {
      targetIndex = i;
      break;
    }
  }
  if (targetIndex >= 0) {
    messages[targetIndex] = {
      ...messages[targetIndex],
      content: withPromptCacheOnContent(messages[targetIndex].content, cacheControl),
    };
    next = { ...next, messages };
  }

  return next;
}

function toPositiveInteger(value, fallback = 0) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : fallback;
}

function applyAnthropicThinking(payload, data, channel = {}) {
  if (data.output_config && typeof data.output_config === 'object') {
    payload.output_config = data.output_config;
  }

  if (data.thinking && typeof data.thinking === 'object') {
    payload.thinking = data.thinking;
  } else if (channel.anthropic_thinking_type === 'enabled') {
    const budgetTokens = toPositiveInteger(channel.anthropic_thinking_budget_tokens, 32000);
    payload.thinking = { type: 'enabled', budget_tokens: budgetTokens };
    if (payload.max_tokens <= budgetTokens) {
      payload.max_tokens = budgetTokens + 1024;
    }
  } else if (channel.anthropic_thinking_type === 'adaptive') {
    payload.thinking = { type: 'adaptive' };
    if (channel.anthropic_thinking_display) {
      payload.thinking.display = channel.anthropic_thinking_display;
    }
  }

  if (!payload.output_config && channel.anthropic_output_effort) {
    payload.output_config = { effort: channel.anthropic_output_effort };
  }
}

function convertOpenAIChatToAnthropic(data, realModel, channel = {}) {
  const messages = [];
  const system = [];

  for (const message of data.messages || []) {
    if (message.role === 'system') {
      if (typeof message.content === 'string') {
        system.push(message.content);
      }
      continue;
    }

    if (message.role === 'tool') {
      messages.push({
        role: 'user',
        content: [{
          type: 'tool_result',
          tool_use_id: message.tool_call_id || message.id || '',
          content: stringifyToolResultContent(message.content),
        }],
      });
      continue;
    }

    messages.push({
      role: message.role === 'assistant' ? 'assistant' : 'user',
      content: message.role === 'assistant'
        ? convertOpenAIMessageToAnthropicContent(message)
        : convertOpenAIContentToAnthropic(message.content),
    });
  }

  const payload = {
    model: realModel,
    messages,
    max_tokens: data.max_tokens || data.max_completion_tokens || 4096,
  };


  if (channel.prompt_cache_enabled) {
    payload.cache_control = getPromptCacheControl(data, channel);
  }

  if (system.length > 0) payload.system = system.join('\n\n');
  if (typeof data.temperature === 'number') payload.temperature = data.temperature;
  if (typeof data.top_p === 'number') payload.top_p = data.top_p;
  if (typeof data.stop === 'string' || Array.isArray(data.stop)) payload.stop_sequences = Array.isArray(data.stop) ? data.stop : [data.stop];
  const tools = convertOpenAIToolsToAnthropic(data.tools);
  if (tools) payload.tools = tools;
  const toolChoice = convertOpenAIToolChoiceToAnthropic(data.tool_choice);
  if (toolChoice) payload.tool_choice = toolChoice;
  applyAnthropicThinking(payload, data, channel);

  return applyAnthropicPromptCache(payload, data, channel);
}

function convertAnthropicResponseToOpenAI(data, requestedModel) {
  const content = Array.isArray(data.content) ? data.content : [];
  const text = content.map((part) => part?.type === 'text' ? (part.text || '') : '').join('');
  const toolCalls = content
    .filter((part) => part?.type === 'tool_use' && part.name)
    .map((part) => ({
      id: part.id || `call_${newRequestId()}`,
      type: 'function',
      function: {
        name: part.name,
        arguments: JSON.stringify(part.input || {}),
      },
    }));
  const usage = data.usage || {};
  const inputTokens = usage.input_tokens || 0;
  const outputTokens = usage.output_tokens || 0;
  const cacheCreationTokens = usage.cache_creation_input_tokens || 0;
  const cacheReadTokens = usage.cache_read_input_tokens || 0;

  return {
    id: data.id || `chatcmpl-${newRequestId()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: requestedModel,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: text || null,
          ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
        },
        finish_reason: normalizeOpenAIFinishReason(data.stop_reason),
      },
    ],
    usage: {
      prompt_tokens: inputTokens,
      completion_tokens: outputTokens,
      cache_creation_input_tokens: cacheCreationTokens,
      cache_read_input_tokens: cacheReadTokens,
      total_tokens: inputTokens + cacheCreationTokens + cacheReadTokens + outputTokens,
    },
  };
}

function flattenTextContent(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return JSON.stringify(content);
  return content.map((part) => {
    if (typeof part === 'string') return part;
    if (part?.type === 'text') return part.text || '';
    if (typeof part?.text === 'string') return part.text;
    if (typeof part?.content === 'string') return part.content;
    return JSON.stringify(part);
  }).filter(Boolean).join('\n');
}

function convertOpenAIChatToPrompt(data = {}) {
  if (typeof data.prompt === 'string') return data.prompt;
  if (!Array.isArray(data.messages)) return '';
  return data.messages.map((message) => {
    const role = message?.role || 'user';
    const content = flattenTextContent(message?.content);
    if (!content) return '';
    if (role === 'system') return `System:\n${content}`;
    if (role === 'assistant') return `Assistant:\n${content}`;
    if (role === 'tool') return `Tool result:\n${content}`;
    return `User:\n${content}`;
  }).filter(Boolean).join('\n\n');
}

function buildUnlimitedChatPayload(data, realModel) {
  const payload = {
    model: realModel,
    prompt: convertOpenAIChatToPrompt(data),
  };
  for (const key of ['temperature', 'top_p', 'max_tokens', 'max_completion_tokens', 'stop']) {
    if (Object.prototype.hasOwnProperty.call(data, key)) payload[key] = data[key];
  }
  if (payload.max_completion_tokens != null && payload.max_tokens == null) {
    payload.max_tokens = payload.max_completion_tokens;
  }
  delete payload.max_completion_tokens;
  return payload;
}

function buildOpenAIChatCompletion(content, requestedModel, finishReason = 'stop') {
  return {
    id: `chatcmpl-${newRequestId()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: requestedModel,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content,
        },
        finish_reason: normalizeOpenAIFinishReason(finishReason),
      },
    ],
    usage: {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

function reorderYepApiMessages(data) {
  if (!data || !Array.isArray(data.messages) || data.messages.length === 0) return data;
  const messages = data.messages;
  let firstUserIdx = -1;
  for (let i = 0; i < messages.length; i++) {
    if (messages[i].role === 'user') { firstUserIdx = i; break; }
  }
  if (firstUserIdx <= 0) return data; // no leading non-user messages or first is already user
  // Collect system and assistant messages before the first user message
  const leading = messages.slice(0, firstUserIdx);
  const rest = messages.slice(firstUserIdx);
  // Merge leading messages into the system prompt
  const systemParts = [];
  const assistantParts = [];
  for (const msg of leading) {
    if (msg.role === 'system') {
      systemParts.push(typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content));
    } else if (msg.role === 'assistant') {
      assistantParts.push(typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content));
    }
  }
  const newMessages = [];
  const mergedSystem = [
    ...systemParts,
    ...(assistantParts.length ? ['[Character Introduction]\n' + assistantParts.join('\n\n')] : []),
  ].join('\n\n');
  if (mergedSystem) {
    newMessages.push({ role: 'system', content: mergedSystem });
  }
  newMessages.push(...rest);
  return { ...data, messages: newMessages };
}

function sanitizePayloadForUpstream(data, upstreamModel) {
  if (!data || typeof data !== 'object') return { data, removedParams: [] };
  const next = { ...data };
  const removedParams = [];
  const model = String(upstreamModel || next.model || '').toLowerCase();

  if (model.includes('gemini')) {
    for (const key of ['presence_penalty', 'frequency_penalty']) {
      if (Object.prototype.hasOwnProperty.call(next, key)) {
        delete next[key];
        removedParams.push(key);
      }
    }
  }

  if (model.includes('glm') && Array.isArray(next.messages)) {
    const normalizedMessages = next.messages.map((message) => (
      message?.role === 'developer' ? { ...message, role: 'system' } : { ...message }
    ));
    const mergedMessages = [];
    for (const message of normalizedMessages) {
      const previous = mergedMessages[mergedMessages.length - 1];
      if (message?.role === 'system' && previous?.role === 'system') {
        previous.content = [flattenTextContent(previous.content), flattenTextContent(message.content)]
          .filter(Boolean)
          .join('\n\n');
      } else {
        mergedMessages.push(message);
      }
    }
    next.messages = mergedMessages;
  }

  return { data: next, removedParams };
}

function getConfiguredModelParams(channel = {}, requestedModel = '') {
  const params = channel && typeof channel.model_params === 'object' && channel.model_params
    ? channel.model_params
    : {};
  const value = Object.prototype.hasOwnProperty.call(params, requestedModel) ? params[requestedModel] : null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return { ...value };
}

function isForcedNonStreamModel(channelKey = '', modelName = '') {
  if (channelKey !== '反重力') return false;
  const name = String(modelName || '');
  return name === '[反重力]gemini-3.1-pro-low'
    || name === '[反重力]gemini-3.5-flash-extra-low'
    || name === 'gemini-3.1-pro-low'
    || name === 'gemini-3.5-flash-extra-low';
}

function shouldBufferNonStreamResponse(channelKey = '', modelName = '', body = '') {
  return isForcedNonStreamModel(channelKey, modelName);
}

function convertResponsesInputToMessages(input) {
  if (typeof input === 'string') {
    return [{ role: 'user', content: input }];
  }
  if (!Array.isArray(input)) return [{ role: 'user', content: String(input || '') }];

  const messages = [];
  for (const item of input) {
    if (typeof item === 'string') {
      messages.push({ role: 'user', content: item });
      continue;
    }
    if (!item || typeof item !== 'object') continue;
    if (item.role && item.content != null && !item.type) {
      messages.push({ role: item.role, content: item.content });
      continue;
    }
    if (item.type === 'message' && item.role && item.content != null) {
      let content = item.content;
      if (Array.isArray(content)) {
        content = content.map(part => {
          if (typeof part === 'string') return { type: 'text', text: part };
          if (part?.type === 'input_text') return { type: 'text', text: part.text || '' };
          if (part?.type === 'input_image') {
            return { type: 'image_url', image_url: { url: part.image_url || part.url || '' } };
          }
          return part;
        });
      }
      messages.push({ role: item.role, content });
      continue;
    }
    if (item.type === 'function_call') {
      messages.push({
        role: 'assistant',
        content: null,
        tool_calls: [{
          id: item.call_id || item.id || '',
          type: 'function',
          function: {
            name: item.name || '',
            arguments: typeof item.arguments === 'string' ? item.arguments : JSON.stringify(item.arguments || {}),
          },
        }],
      });
      continue;
    }
    if (item.type === 'function_call_output') {
      messages.push({
        role: 'tool',
        tool_call_id: item.call_id || '',
        content: typeof item.output === 'string' ? item.output : JSON.stringify(item.output || ''),
      });
      continue;
    }
  }
  return messages.length > 0 ? messages : [{ role: 'user', content: '' }];
}


function convertResponsesToolChoiceToOpenAI(toolChoice) {
  if (!toolChoice) return undefined;
  if (typeof toolChoice === 'string') return toolChoice;
  if (toolChoice.type === 'auto' || toolChoice.type === 'none' || toolChoice.type === 'required') return toolChoice.type;
  if (toolChoice.type === 'function' && toolChoice.name) {
    return { type: 'function', function: { name: toolChoice.name } };
  }
  if (toolChoice.type === 'function' && toolChoice.function?.name) {
    return { type: 'function', function: { name: toolChoice.function.name } };
  }
  return toolChoice;
}

function convertResponsesToolsToOpenAI(tools) {
  if (!Array.isArray(tools)) return undefined;
  return tools.map(tool => {
    if (tool?.type === 'function') {
      return {
        type: 'function',
        function: {
          name: tool.name || '',
          description: tool.description || '',
          parameters: tool.parameters || { type: 'object', properties: {} },
        },
      };
    }
    return null;
  }).filter(Boolean);
}

function convertChatCompletionToResponsesFormat(chatResult, requestedModel) {
  const choice = chatResult.choices?.[0];
  const message = choice?.message || {};
  const outputItems = [];
  const contentParts = [];
  if (message.content) {
    contentParts.push({ type: 'output_text', text: message.content, annotations: [] });
  }
  if (Array.isArray(message.tool_calls)) {
    for (const tc of message.tool_calls) {
      outputItems.push({
        type: 'function_call',
        id: tc.id || ('call_' + newRequestId()),
        call_id: tc.id || ('call_' + newRequestId()),
        name: tc.function?.name || '',
        arguments: tc.function?.arguments || '{}',
        status: 'completed',
      });
    }
  }
  if (contentParts.length > 0) {
    outputItems.push({
      type: 'message',
      id: 'msg_' + newRequestId(),
      role: 'assistant',
      status: 'completed',
      content: contentParts,
    });
  }
  const usage = chatResult.usage || {};
  return {
    id: (chatResult.id || '').replace('chatcmpl-', 'resp_') || ('resp_' + newRequestId()),
    object: 'response',
    created_at: chatResult.created || Math.floor(Date.now() / 1000),
    model: requestedModel || chatResult.model,
    status: 'completed',
    output: outputItems,
    output_text: message.content || null,
    usage: {
      input_tokens: usage.prompt_tokens || 0,
      output_tokens: usage.completion_tokens || 0,
      total_tokens: usage.total_tokens || 0,
    },
    metadata: {},
  };
}

function convertAnthropicMessagesToOpenAIChat(data) {
  const messages = [];
  if (data.system) {
    if (typeof data.system === 'string') {
      messages.push({ role: 'system', content: data.system });
    } else if (Array.isArray(data.system)) {
      const text = data.system.map(p => p?.text || '').filter(Boolean).join('\n\n');
      if (text) messages.push({ role: 'system', content: text });
    }
  }
  for (const msg of data.messages || []) {
    if (msg.role === 'user' || msg.role === 'assistant') {
      let content = msg.content;
      if (Array.isArray(content)) {
        // Handle tool_result in user messages separately
        const toolResults = content.filter(p => p?.type === 'tool_result');
        content = content.filter(p => p?.type !== 'tool_result' && p?.type !== 'tool_use').map(part => {
          if (typeof part === 'string') return { type: 'text', text: part };
          if (part?.type === 'text') return { type: 'text', text: part.text || '' };
          if (part?.type === 'image') {
            return {
              type: 'image_url',
              image_url: {
                url: part.source?.type === 'base64'
                  ? ('data:' + (part.source.media_type || 'image/png') + ';base64,' + part.source.data)
                  : (part.source?.url || ''),
              },
            };
          }
          return part;
        });
        if (content.length === 1 && content[0].type === 'text') content = content[0].text;
        else if (content.length === 0) content = '';

        // Handle tool_use in assistant messages
        const toolCalls = [];
        if (msg.role === 'assistant') {
          for (const part of msg.content) {
            if (part?.type === 'tool_use') {
              toolCalls.push({
                id: part.id || ('call_' + newRequestId()),
                type: 'function',
                function: {
                  name: part.name,
                  arguments: typeof part.input === 'string' ? part.input : JSON.stringify(part.input || {}),
                },
              });
            }
          }
        }
        const message = { role: msg.role, content };
        if (toolCalls.length > 0) message.tool_calls = toolCalls;
        messages.push(message);

        // Add tool results as separate tool messages
        for (const tr of toolResults) {
          messages.push({
            role: 'tool',
            tool_call_id: tr.tool_use_id || '',
            content: typeof tr.content === 'string' ? tr.content : JSON.stringify(tr.content || ''),
          });
        }
      } else {
        messages.push({ role: msg.role, content });
      }
    }
  }
  return messages;
}

function convertOpenAIChatResultToAnthropicMessages(chatResult, requestedModel) {
  const choice = chatResult.choices?.[0];
  const message = choice?.message || {};
  const content = [];
  if (message.content) {
    content.push({ type: 'text', text: message.content });
  }
  if (Array.isArray(message.tool_calls)) {
    for (const tc of message.tool_calls) {
      let input = {};
      try { input = JSON.parse(tc.function?.arguments || '{}'); } catch { input = {}; }
      content.push({
        type: 'tool_use',
        id: tc.id || ('toolu_' + newRequestId()),
        name: tc.function?.name || '',
        input,
      });
    }
  }
  const usage = chatResult.usage || {};
  const finishReason = choice?.finish_reason;
  let stopReason = 'end_turn';
  if (finishReason === 'length') stopReason = 'max_tokens';
  else if (finishReason === 'tool_calls') stopReason = 'tool_use';
  return {
    id: (chatResult.id || '').replace('chatcmpl-', 'msg_') || ('msg_' + newRequestId()),
    type: 'message',
    role: 'assistant',
    model: requestedModel || chatResult.model,
    content,
    stop_reason: stopReason,
    stop_sequence: null,
    usage: {
      input_tokens: usage.prompt_tokens || 0,
      output_tokens: usage.completion_tokens || 0,
      cache_creation_input_tokens: usage.cache_creation_input_tokens || 0,
      cache_read_input_tokens: usage.cache_read_input_tokens || 0,
    },
  };
}


export {
  escapeRegExp,
  stripModelPrefix,
  convertOpenAIContentToAnthropic,
  normalizeOpenAIFinishReason,
  convertOpenAIToolsToAnthropic,
  convertOpenAIToolChoiceToAnthropic,
  stringifyToolResultContent,
  convertOpenAIMessageToAnthropicContent,
  buildPromptCacheControl,
  getPromptCacheControl,
  getAnthropicBetaHeader,
  contentPartHasPromptCache,
  messageHasPromptCache,
  withPromptCacheOnContent,
  systemHasPromptCache,
  withPromptCacheOnSystem,
  applyOpenAICompatiblePromptCache,
  applyAnthropicPromptCache,
  toPositiveInteger,
  applyAnthropicThinking,
  convertOpenAIChatToAnthropic,
  convertAnthropicResponseToOpenAI,
  flattenTextContent,
  convertOpenAIChatToPrompt,
  buildUnlimitedChatPayload,
  buildOpenAIChatCompletion,
  reorderYepApiMessages,
  sanitizePayloadForUpstream,
  getConfiguredModelParams,
  isForcedNonStreamModel,
  shouldBufferNonStreamResponse,
  convertResponsesInputToMessages,
  convertResponsesToolChoiceToOpenAI,
  convertResponsesToolsToOpenAI,
  convertChatCompletionToResponsesFormat,
  convertAnthropicMessagesToOpenAIChat,
  convertOpenAIChatResultToAnthropicMessages,
};
