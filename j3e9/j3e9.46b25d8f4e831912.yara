
rule j3e9_46b25d8f4e831912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.46b25d8f4e831912"
     cluster="j3e9.46b25d8f4e831912"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor poison poisonivy"
     md5_hashes="['a0cc12affb459d48cfc4dad8764904bf','a38ff2ee39974e8b9048af6810d3107e','d4b39c2c651505f46c988ad7417074b2']"

   strings:
      $hex_string = { 14583a61de1b111c320f9c165318f222fe44cfb2c3b57a912408e8a860fc6950aad0a07da1896297545b1e95e0ff64d210c40048a3f775db8a03e6da093fdd94 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
