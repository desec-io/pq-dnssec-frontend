<template>
  <v-container>
    <v-row class="text-center">
      <v-col class="mb-4 mt-4">
        <h1 class="display-2 font-weight-bold mb-3">
          Post-Quantum DNSSEC Testbed with BIND and PowerDNS
        </h1>
      </v-col>
    </v-row>

    <v-row id="intro">
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
          implementations for PowerDNS and BIND (source links above).
        </p>
        <p>
          Zones signed accordingly are available at <code>{algorithm}.{vendor}.pq-dnssec.dedyn.io</code>, and each has a
          <code>A</code> and a <code>TXT</code> record configured (apart from DNSSEC records like <code>DNSKEY</code>).
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
        <v-form v-model="valid" @submit.prevent="query">
          <v-row>
            <v-combobox
              v-model="qtype"
              filled
              label="Query type"
              :rules="[v => !!v || 'You must enter a type.']"
              :items="['DNSKEY', 'A', 'TXT']"
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
            <v-select v-model="vendorAuth" label="Authoritative vendor" :items="vendors" item-title="name" item-value="value"/>
            <v-select v-model="vendorRes" label="Resolver vendor" :items="vendors" item-title="name" item-value="value"/>
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
                <v-btn type="submit" variant="flat" class="mr-2" color="primary">
                  <v-icon class="mr-1">mdi-send</v-icon>
                  Query
                </v-btn>
                <v-btn variant="flat" :href="`https://dnsviz.net/d/${qname}/dnssec/`" target="_blank" class="text-none" color="secondary">
                  DNSViz
                  <v-icon class="ml-1">mdi-open-in-new</v-icon>
                </v-btn>
              </template>
            </v-text-field>
          </v-row>
        </v-form>
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
        <v-row ref="output">
          <code v-if="!working && r_text.length" style="background: lightgrey; padding: 1em; width: 100%; overflow-wrap: break-word"><span
            v-for="(l, index) in r_text"
            :key="index"
          >{{ l }}<br></span></code>
        </v-row>
      </v-col>
    </v-row>

    <v-row>
      <v-col
        class="mb-5"
        cols="12"
      >
        <h2 class="headline font-weight-bold mb-3">
          Field Study
        </h2>
        <p>
          In order to investigate DNS response success and failure rates depending on the signing scheme and other
          parameters, a RIPE ATLAS field study based on our
          <a href="/study-concept.pdf" target="_blank">measurement and analysis concept <v-icon>mdi-open-in-new</v-icon></a>
          was conducted with the above implementations.
        </p>

        <h3>Results</h3>
        <p>
          RIPE ATLAS measurements are available both
          <a href="https://atlas.ripe.net/measurements/public?id__gt=1000000&is_public=true&sort=-id&toggle=all&page_size=100&search=pq-dnssec.dedyn.io&page=1" target="_blank">raw <v-icon>mdi-open-in-new</v-icon></a> and as a
          <a href="/results.csv.bz2" target="_blank">pre-processed CSV file <v-icon>mdi-open-in-new</v-icon></a>.
          We further provide the
          <a href="/Analysis.ipynb" target="_blank">analysis notebook <v-icon>mdi-open-in-new</v-icon></a>, the outputs
          of which are available separately
          <a href="/results_bind9_good-rsa.pdf" target="_blank">for BIND <v-icon>mdi-open-in-new</v-icon></a> and
          <a href="/results_pdns_good-rsa.pdf" target="_blank">for PowerDNS <v-icon>mdi-open-in-new</v-icon></a>.
        </p>
        <p>
          We find that depending on circumstances, a significant fraction of clients choke. Failure rates are mainly a
          function of response packet size, which is mediated by parameters such as DNSSEC configuration (KSK/ZSK vs.
          CSK, NSEC vs. NSEC3, or compact DoE) and DO bit presence, with some variation depending on transport.
          This is qualitatively in line with the "educated guess", but adds quantitative detail.
        </p>
        <p>
          We also find surprising results, such as that a number of resolvers claim to have validated PQC signatures,
          even though it is implausible for resolvers to support these algorithms.
        </p>
      </v-col>
    </v-row>

    <v-row>
      <v-col
        class="mb-5"
        cols="12"
      >
        <h2 class="headline font-weight-bold mb-3">
          Benchmarks
        </h2>
        <p>
          Each benchmark has 10,000 runs for key generation, signing, and validation.
        </p>
        <ul class="pl-6">
          <li>
            <a href="/benchmark_pdns.pdf" target="_blank">PowerDNS benchmark <v-icon>mdi-open-in-new</v-icon></a> using
            100 runs of the on-board <code>pdnsutil</code> tool (runs 100 iterations each)
          </li>
          <li>
            <a href="/benchmark_bind9.pdf" target="_blank">BIND9 benchmark <v-icon>mdi-open-in-new</v-icon></a> using
            10,000 runs of <code>dnssec-keygen</code>, and single runs of <code>dnssec-signzone</code> on a suitable
            sized test zone
          </li>
        </ul>
        <p>
          Results show overall agreement and demonstrate PQC algorithms performing en par with classical algorithms,
          with the exception of XMSS which has prohibitively large key generation time.
        </p>

        <h3>Limitations:</h3>
        <ul class="pl-6">
          <li>
            BIND key generation is bounded from below because individual passes were necessary, causing around 8ms
            overhead per invocation. For EC and Dilithium2, overhead and actual key generation take comparably long,
            leaving room for efficiency improvements in <code>dnssec-keygen</code>.
          </li>
          <li>
            Measurements were conducted on VMs with unknown neighbor noise and slightly different configuration. While
            absolute numbers vary up to a factor of 2, shape is preserved.
          </li>
        </ul>
        <p>The above key takeaway nevertheless can be extracted.</p>
      </v-col>
    </v-row>

    <v-row>
      <v-col
        class="mb-5"
        cols="12"
      >
        <h2 class="headline font-weight-bold mb-3">
          Publications
        </h2>
        <ul class="pl-6">
          <li>
            2024-07-24 <a href="https://datatracker.ietf.org/doc/slides-120-maprg-field-experiments-on-post-quantum-dnssec/" target="_blank">Final Results at IETF MAPRG <v-icon>mdi-open-in-new</v-icon></a>
            (Vancouver)
          </li>
          <li>
            2024-07-21 <a href="https://iepg.org/2024-07-21-ietf120/slides-120-iepg-sessa-field-experiments-on-post-quantum-dnssec-00.pdf" target="_blank">Final Results at IEPG July 2024 <v-icon>mdi-open-in-new</v-icon></a>
            (Vancouver)
          </li>
          <li>
            2024-07-16 <a href="https://www.isc.org/blogs/2024-pqc-study/" target="_blank">BIND &amp; liboqs: A PQC DNSSEC Field Study <v-icon>mdi-open-in-new</v-icon></a>
            (ISC/BIND blog)
          </li>
          <li>
            2024-07-15 <a href="https://blog.powerdns.com/2024/07/15/more-pqc-in-powerdns-a-dnssec-field-study" target="_blank">More PQC in PowerDNS: A DNSSEC Field Study <v-icon>mdi-open-in-new</v-icon></a>
            (PowerDNS blog)
          </li>
          <li>
            2024-07-11 <a href="https://blog.apnic.net/2024/07/11/podcast-testing-post-quantum-cryptography-dnssec/" target="_blank">Testing Post Quantum Cryptography DNSSEC <v-icon>mdi-open-in-new</v-icon></a>
            (PING Podcast)
          </li>
          <li>
            2024-06-10 <a href="https://static.sched.com/hosted_files/icann80/11/2.6%20Peter%20Thomassen%202024-06-10%20ICANN%2080%2C%20Field%20Experiments%20on%20Post-Quantum%20DNSSEC.pdf" target="_blank">Preliminary Results at ICANN 80 <v-icon>mdi-open-in-new</v-icon></a>
            (Kigali), BIND9 only
          </li>
        </ul>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import {sendDohMsg} from 'dohjs'
import {RECURSION_DESIRED} from 'dns-packet'
//import base32 from 'hi-base32'

  export default {
    name: 'QueryPage',

    data: () => ({
      valid: null,
      algorithm: 'Falcon512',
      vendorAuth: ['pdns', 'bind9'][Math.floor(Math.random() * 2)],
      vendorRes: ['pdns', 'bind9'][Math.floor(Math.random() * 2)],
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
        return `${this.nx ? 'nx.' : ''}${this.algorithm.toLowerCase()}${this.nsec3 ? 3 : ''}.${this.vendorAuth}.pq-dnssec.dedyn.io`;
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
        if (!this.valid) {
          return;
        }
        this.working = true
        this.r_text = []
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
        sendDohMsg(this.q, `https://${this.vendorRes}.pq-dnssec.dedyn.io/dns-query`, 'GET', [], 3000)
          .then(r => {this.digest(r); this.working = false;})
          .catch(err => {this.err = err; this.working = false;})
      },
      digest: function (r) {
        this.r_text = []
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
        this.$nextTick(() => {
          this.$refs.output.$el.scrollIntoView();
        });
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
            } else if (rrset.type == 'DNSKEY') {
              full_rrset_txt += `${rrset.data.flags} 3 ${rrset.data.algorithm} ${rrset.data.key.toString('base64')}`
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
a {
  text-decoration: none;
}
p {
  margin: 1em 0;
}
#intro code {
  background: #FEE;
  font-weight: 600;
  padding: 2px;
}
</style>