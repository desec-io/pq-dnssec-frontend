<template>
  <v-container>
    <v-row class="text-center">
      <v-col class="mb-4 mt-4">
        <h1 class="display-2 font-weight-bold mb-3">
          Post-Quantum DNSSEC Testbed with BIND and PowerDNS
        </h1>
      </v-col>
    </v-row>

    <v-row>
      <v-col
        class="mb-5"
        cols="12"
      >
        <h2 class="headline font-weight-bold mb-3">
          Query our PQC-enabled DNS Resolvers
        </h2>
        <p>
          Send queries to our post-quantum enabled validating resolver!
          You can choose from a number of post-quantum (and classical) signing schemes, NSEC or NSEC3 mode, and
          implementations for PowerDNS or BIND.
        </p>
        <p>
          Zones signed accordingly are available at <code>{algorithm}.{vendor}.pq-dnssec.dedyn.io</code>, and each has a
          <code>A</code> and a <code>TXT</code> record configured.
          To query a non-existing name, prepend the <code>nx</code> label (for example).
        </p>
        <p>
          Queries will be sent from your browser using DNS-over-HTTPS to a BIND or PowerDNS resolvers with validation
          support for the selected algorithm.
          The resolver will talk to the corresponding BIND or PowerDNS authoritative DNS server (again, with support for
          the selecting signing scheme), to get your response.
          It will then validate the signature and send the result to your browser.
        </p>
        <p>
          All queries are send with the <code>DNSSEC_OK</code> flag (<code>+dnssec</code> in dig), so you will see
          <code>RRSIG</code> and <code>NSEC</code>/<code>NSEC3</code> records the the responses.
        </p>
      </v-col>
    </v-row>

    <v-row>
      <v-col>
        <v-row>
          <v-combobox
            v-model="qtype"
            filled
            label="Query type"
            :items="['TXT', 'A']"
          />
          <v-select v-model="algorithm" label="Algorithm" :items="algorithms">
            <template #item="{ props, item }">
              <v-list-subheader v-if="props.header">
                {{ props.header }}
              </v-list-subheader>
              <v-divider v-else-if="props.divider" class="mt-2" />
              <v-list-item v-else v-bind="props"></v-list-item>
            </template>
          </v-select>
          <v-select v-model="vendor" label="vendor" :items="vendors" item-title="name" item-value="value"/>
        </v-row>
        <v-row>
          <v-checkbox
            v-model="nsec3"
            label="NSEC3"
            :readonly="algorithm == 'unsigned'"
          />
          <v-checkbox
            v-model="nx"
            label="non-existent name"
          />
          <v-text-field
            v-model="qname"
            filled
            label="Domain name"
            readonly
            type="text"
            class="ml-2"
          >
            <template v-slot:append>
              <v-icon :disabled="!qtype || !qname" @click="query">mdi-send</v-icon>
            </template>
          </v-text-field>
        </v-row>
        <v-row v-if="working">
          <v-col>
            <div class="text-center">
              <v-progress-circular
                indeterminate
                color="primary"
              />
            </div>
          </v-col>
        </v-row>
        <v-row v-if="err">
          <v-alert>{{ err }}</v-alert>
        </v-row>
        <v-row v-if="!working && r_text.length">
          <code style="background: lightgrey; padding: 1em; width: 100%; overflow-wrap: break-word"><span
            v-for="(l, index) in r_text"
            :key="index"
          >{{ l }}<br></span></code>
        </v-row>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import {sendDohMsg} from 'dohjs'
import {RECURSION_DESIRED} from 'dns-packet'
import base32 from 'hi-base32'

  export default {
    name: 'HelloWorld',

    data: () => ({
      algorithm: 'Falcon512',
      vendor: ['pdns', 'bind9'][Math.floor(Math.random() * 2)],
      nx: false,
      nsec3: false,
      qtype: null,
      q: '',
      r_text: [],
      working: false,
      err: false,
      algorithms: [
        'unsigned',
        { props: { header: 'Classical' }},
        'RSASHA256',
        'ECDSA256',
        'ED25519',
        { props: { header: 'Post-quantum' }},
        'Falcon512',
        'Dilithium2',
        'Sphincs-SHA256-128s',
        'XMSSmt-SHA256-h40-4',
        'XMSSmt-SHA256-h40-8',
      ],
      vendors: [
        { name: 'BIND', value: 'bind9' },
        { name: 'PowerDNS', value: 'pdns' },
      ],
    }),
    computed: {
      qname: function () {
        return `${this.nx ? 'nx.' : ''}${this.algorithm.toLowerCase()}${this.nsec3 ? 3 : ''}.${this.vendor}.pq-dnssec.dedyn.io`;
      },
    },
    watch: {
      algorithm: function (algo) {
        if (algo == 'unsigned') {
          this.nsec3 = false;
        }
      }
    },
    methods: {
      query: function () {
        this.working = true
        this.err = false
        this.q = {
            type: 'query',
            id: 0,
            flags: RECURSION_DESIRED,
            questions: [{
              type: this.qtype,
              name: this.qname,
            }],
            additionals: [{
              type: 'OPT',
              name: '.',
              udpPayloadSize: 4096,
              flags: 1 << 15, // DNSSEC_OK
            }]
        }
        sendDohMsg(this.q, 'https://pdns.pq-dnssec.dedyn.io/dns-query', 'GET', [], 1500)
          .then(r => {this.digest(r); this.working = false;})
          .catch(err => {this.err = err; this.working = false;})
      },
      digest: function (r) {
        this.r_text = []
        // this.r_text.push(r)

        // Header:
        // ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25078
        // ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 1
        this.r_text.push(`;; ->>HEADER<<- opcode: ${r.opcode}, status: ${r.rcode}, id: ${r.id}`)
        let flags = []
        if (r.flag_qr) flags.push('qr')
        if (r.flag_aa) flags.push('aa')
        if (r.flag_tc) flags.push('tc')
        if (r.flag_rd) flags.push('rd')
        if (r.flag_ra) flags.push('ra')
        if (r.flag_z) flags.push('z')
        if (r.flag_ad) flags.push('ad')
        if (r.flag_cd) flags.push('cd')
        this.r_text.push(`;; flags: ${flags.join(' ')}; QUERY: ${r.questions.length}, ANSWER: ${r.answers.length}, AUTHORITY: ${r.authorities.length}, ADDITIONAL: ${r.additionals.length}`)
        this.r_text.push('')

        // Question
        this.r_text.push(';; QUESTION SECTION:')
        this.r_text.push(...this.render_section(r.questions))
        this.r_text.push('')

        // Answer
        this.r_text.push(';; ANSWER SECTION:')
        this.r_text.push(...this.render_section(r.answers))
        this.r_text.push('')

        // Authority
        if (r.authorities.length) {
          this.r_text.push(';; AUTHORITY SECTION:')
          this.r_text.push(...this.render_section(r.authorities))
          this.r_text.push('')
        }
      },
      render_section(s) {
        let full_section = []
        s.forEach((rrset) => {
          let full_rrset_txt = ''
          if (rrset.data) {
            full_rrset_txt = `${rrset.name} ${rrset.ttl} ${rrset.class} ${rrset.type} `
            if (rrset.type == 'RRSIG')
              full_rrset_txt += (
                  `${rrset.data.typeCovered} ${rrset.data.algorithm} ${rrset.data.labels} ${rrset.data.originalTTL} ` +
                  `${rrset.data.inception} ${rrset.data.expiration} ${rrset.data.keyTag} ${rrset.data.signersName} ` +
                  `${rrset.data.signature.toString('base64')}`
              )
            else if (rrset.type == 'TXT') {
              rrset.data.forEach((rr) => {
                full_rrset_txt += `"${rr.toString()}" `
              })
            } else if (rrset.type == 'A' || rrset.type == 'AAAA') {
              full_rrset_txt += rrset.data
            } else if (rrset.type == 'SOA') {
              // { "name": "falcon3.example", "type": "SOA", "ttl": 3600, "class": "IN", "flush": false,
              // "data": { "mname": "a.misconfigured.dns.server.invalid", "rname": "hostmaster.falcon3.example", "serial": 0, "refresh": 10800, "retry": 3600, "expire": 604800, "minimum": 3600 } }
              // a.misconfigured.dns.server.invalid. hostmaster.falcon.example.pq-dnssec.dedyn.io. 0 10800 3600 604800 3600
              full_rrset_txt += `${rrset.data.mname} ${rrset.data.rname} ${rrset.data.serial} ${rrset.data.refresh} ${rrset.data.retry} ${rrset.data.expire} ${rrset.data.minimum}`
            } else if (rrset.type == 'NSEC') {
              full_rrset_txt += `${rrset.data.nextDomain} ${rrset.data.rrtypes.join(' ')}`
            } else if (rrset.type == 'NSEC3') {
              // For some reason, ${base32.encode(rrset.data.nextDomain)} does not give same output as dig; eliding
              full_rrset_txt += `${rrset.data.algorithm} ${rrset.data.flags} ${rrset.data.iterations} ${rrset.data.salt.length ? rrset.data.salt.toString('hex') : '-'} ... ${rrset.data.rrtypes.join(' ')}`
            } else {
              full_rrset_txt = rrset
            }
          } else {
            full_rrset_txt = `${rrset.name} ${rrset.class} ${rrset.type}`
          }
          full_section.push(full_rrset_txt)
        })
        return full_section
      }
    },
  }
</script>

<style>
p {
  margin: 1em 0;
}
p code {
  background: #FEE;
  font-weight: 600;
  padding: 2px;
}
</style>