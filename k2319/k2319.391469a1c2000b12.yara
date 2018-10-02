
rule k2319_391469a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391469a1c2000b12"
     cluster="k2319.391469a1c2000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0c2975631a084f483fc4dc5de51d2fd1107575bc','498f29e20884db18dbdd83c54758a650d1e3178a','2c1c35d969fbbd87162a2f1f868fe2da3286b4e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391469a1c2000b12"

   strings:
      $hex_string = { 362e33304531293f283134352e2c277927293a2832312c372e304532292929627265616b7d3b766172204736483d7b274c334e273a225455564d222c2742394e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
