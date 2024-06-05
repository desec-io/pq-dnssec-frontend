<template>
  <v-app>
        <v-app-bar
      app
      color="primary"
      dark
    >

      <v-spacer></v-spacer>

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