
rule k3e9_33ac369b9b4ee113
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.33ac369b9b4ee113"
     cluster="k3e9.33ac369b9b4ee113"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="peed backdoor qukart"
     md5_hashes="['a447f7a1b6f0b550c247218c6b4293d1','be818e4f66beff7bea60bacd9e4470ae','e715cbda644c0d3b5eabee90e9fb11b2']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
