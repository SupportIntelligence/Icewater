
rule k2319_5846a49699eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5846a49699eb0912"
     cluster="k2319.5846a49699eb0912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script asmalwsc"
     md5_hashes="['84d1b233544779c36f261508e845113140113afe','a3d0d45adf3681ad649989f15eff2d14835c0ef7','aeaa450851d58ab0fa3a843f0a824e799d709389']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5846a49699eb0912"

   strings:
      $hex_string = { 646566696e6564297b72657475726e20525b4b5d3b7d76617220493d282836352c313038293c2837392e313045312c3438293f2835392e3245312c227a22293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
