<template>
  <v-footer
    height="40"
    app
  >
    <a
      v-for="item in items"
      :key="item.title"
      :href="item.href"
      :title="item.title"
      class="d-inline-block mx-2 social-link"
      rel="noopener noreferrer"
      target="_blank"
    >
      <v-icon
        :icon="item.icon"
        :size="item.icon === '$vuetify' ? 24 : 16"
      />
    </a>
    <div
      class="text-caption text-disabled"
    >
      <span class="d-none d-sm-inline">
        Credits:
        <a href="https://goertzen.dev/">Jason Goertzen</a> (<a href="https://www.sandboxaq.com/">Sandbox AQ</a>),
        <a href="https://github.com/nils-wisiol/dns-falcon">Nils Wisiol</a>.
      </span>
      <a href="https://nlnet.nl/project/PQ-DNSSEC-Testbench/">Funded by NLnet<span class="d-none d-sm-inline"> Foundation</span>.</a>
    </div>

    <div
      class="text-caption text-disabled"
      style="position: absolute; right: 16px;"
    >
      &copy; 2022-{{ (new Date()).getFullYear() }} <span class="d-none d-sm-inline-block"><a href="https://desec.io/">deSEC e.V.</a></span>
      —
      <a
        class="text-decoration-none on-surface"
        href="https://vuetifyjs.com/about/licensing/"
        rel="noopener noreferrer"
        target="_blank"
      >
        MIT License
      </a>
    </div>
  </v-footer>
</template>

<script setup>
  const items = [
    {
      title: 'GitHub for this web interface',
      icon: `mdi-github`,
      href: 'https://github.com/desec-io/pq-dnssec-frontend',
    },
  ]
</script>

<style scoped lang="sass">
  .social-link :deep(.v-icon)
    color: rgba(var(--v-theme-on-background), var(--v-disabled-opacity))
    text-decoration: none
    transition: .2s ease-in-out

    &:hover
      color: rgba(25, 118, 210, 1)
</style>
