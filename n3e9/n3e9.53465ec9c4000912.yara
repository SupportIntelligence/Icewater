
rule n3e9_53465ec9c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53465ec9c4000912"
     cluster="n3e9.53465ec9c4000912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler backdoor"
     md5_hashes="['0579f78f5812dd6862c31c737a6dcdd0','b57a21864b0f81ae15e891829332dba9','b640b1b50729d47667f050c8fc50f840']"

   strings:
      $hex_string = { 0043006f00640065003a002000250064002e000a00250073001b0041002000570069006e003300320020004100500049002000660075006e006300740069006f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
