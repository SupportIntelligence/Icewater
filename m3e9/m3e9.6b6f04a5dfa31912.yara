
rule m3e9_6b6f04a5dfa31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f04a5dfa31912"
     cluster="m3e9.6b6f04a5dfa31912"
     cluster_size="201"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['022692097ead87052739adee7ff366c2','080a5be620e812c54f1dfad76ee904fe','47cd2cfd3d75bff190239f8bdcd02077']"

   strings:
      $hex_string = { 108c0e59956cd96936433215bc15f3d73917dab79f55ed6b4b3433119a78e7e06f076149336c94a7b354d358500bc09e0050c9c62596ff521082d21029be2fc5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
