
rule m3e9_15a05cc3cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.15a05cc3cc000932"
     cluster="m3e9.15a05cc3cc000932"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['00ce6c6a8a12289b568e0abd3f138f50','069a55a941dac1046fb6bb8d93b072f7','96400fb34d1b44085e270679dc6c12cc']"

   strings:
      $hex_string = { 208b088a1180fa30721780fa3977126bdb0a410fb6d2478d5c13d089083bce76db85ff761681fb00010000730e8b4d10b00188195f5e5b5dc20c0032c0ebf5cc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
