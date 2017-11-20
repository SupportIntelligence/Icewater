
rule k2321_2355eced96264aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2355eced96264aba"
     cluster="k2321.2355eced96264aba"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['23fd8d6e6f1b3c2ec192e11168f45431','6c104696d0c004586dd06f33ce3332df','b93f402e9ac450e3897dd87473e873c1']"

   strings:
      $hex_string = { e18ceca271f9d2845cf49af4e45c724d62cac412e9f0dce269e3f2a4434ba665e64e491f1e1ba9c6293c6850522c5777ea3e90b7351df71491cf805588e701d6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
