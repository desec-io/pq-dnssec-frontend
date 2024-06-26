<template>
  <v-app>
        <v-app-bar
      app
      color="primary"
      dark
    >

      <v-spacer></v-spacer>

      <v-btn
          href="https://static.sched.com/hosted_files/icann80/11/2.6%20Peter%20Thomassen%202024-06-10%20ICANN%2080%2C%20Field%20Experiments%20on%20Post-Quantum%20DNSSEC.pdf"
          target="_blank"
          text
      >
        <span class="mr-2">Preliminary Results at ICANN 80</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>

      <v-btn
        href="mailto:pqc@desec.io"
        target="_blank"
        text
      >
        <span class="mr-2">Contact</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main>
      <QueryPage />
    </v-main>

    <AppFooter />
  </v-app>
</template>

<script setup>
  //
import QueryPage from "@/components/QueryPage.vue";
</script>

<style>
a {
  color: rgb(var(--v-theme-primary));
}
</style>