
rule m3e9_0b54ab99c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b54ab99c6220b12"
     cluster="m3e9.0b54ab99c6220b12"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0b51a83fe09adc17978af1e06af935f3','18225c466b807d8a0dbc1e5bd61d0c88','7689ebb7df51b0a2b95fdc6742e71b42']"

   strings:
      $hex_string = { 3f543b590e0281aa0b70c974b116c0aeaeeebc001471d4fc1a386fd6ad2429785739099fdc0a80211f3413a67fe8b03196a879c2ba206ef24776bf077b36eb5f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
