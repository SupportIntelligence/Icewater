
rule m3e9_19e04a96a90bd132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.19e04a96a90bd132"
     cluster="m3e9.19e04a96a90bd132"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="barys vbna virut"
     md5_hashes="['0a44b118e62be992dc1a47d3c109da30','1e4bfddb5fc77f57acef854228bdb695','dbd8e43b7f92842a3c867ce6d444a6aa']"

   strings:
      $hex_string = { 01233e10e389ab855e64a31707c1793a7242c7dc0b588bd2e850e0314f3a09f5fab02cfdecb27f144e0c2980cdc3950a682a087e25186616d6673b37e21a8e34 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
