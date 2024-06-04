// Plugins
import { registerPlugins } from '@/plugins'

// Components
import App from './App.vue'

// Composables
import { createApp } from 'vue'

const app = createApp(App)

registerPlugins(app)

app.mount('#app')

process.nextTick = (function () {
    if (typeof window !== 'undefined' && window.setImmediate) {
        return function (f, ...params) { return window.setImmediate(f, ...params) };
    }
    if (typeof window !== 'undefined' && window.postMessage && window.addEventListener) {
        var queue = [];
        window.addEventListener('message', function (ev) {
            if ((ev.source === window || ev.source === null) && ev.data === 'process-tick') {
                ev.stopPropagation();
                if (queue.length > 0) {
                    var { fn, params } = queue.shift();
                    fn(...params);
                }
            }
        }, true);
        return function nextTick(fn, ...params) {
            queue.push({ fn, params });
            window.postMessage('process-tick', '*');
        };
    }
    return function nextTick(fn, ...params) {
        setTimeout(fn, 0, ...params);
    };
})();
