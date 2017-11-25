
rule k3e9_29b56a9983592192
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29b56a9983592192"
     cluster="k3e9.29b56a9983592192"
     cluster_size="122"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis convertad"
     md5_hashes="['00374467dbb77284be810ebf67d2b6f1','05a1d211ac30261770efa28516f4ab1e','217c170241c90214be92c0e5663321a8']"

   strings:
      $hex_string = { 55947d2983659800ebc3ff45988b45983b45a47cb86afc586a18598dbb64e837008d7594f3a55f5e5bc9c2040033f632c93975a47e1033c0884c05f4fec10fb6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
