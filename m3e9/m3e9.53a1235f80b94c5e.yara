
rule m3e9_53a1235f80b94c5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53a1235f80b94c5e"
     cluster="m3e9.53a1235f80b94c5e"
     cluster_size="47"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['04ae8e08ee0038f126304a49c281f53e','04f912e1bf56c6c8a1d8068723c3e20f','47f18a7df5fb7fa7f894b9f33e57c03a']"

   strings:
      $hex_string = { caeebdf5de3fe52c6b18ed4d9c8f6ab01e65ade831fc752579d4d5be961d295505d2a74e54159078915287da81a122f72eea23b6ab92c69a398a936041535f7b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
