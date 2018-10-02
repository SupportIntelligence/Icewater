
rule k2319_6814eaca99ab0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6814eaca99ab0b12"
     cluster="k2319.6814eaca99ab0b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script asmalwsc"
     md5_hashes="['1d66bab24b94deec29bbc896aa3c7bbaebf6156c','7fec2f4c34cf1113a173559ff32332ac90afefc2','72ad371772e56c807c05f7d477daacb052313e06']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6814eaca99ab0b12"

   strings:
      $hex_string = { 38293f28307837382c313130293a2835332c3078314538292929627265616b7d3b76617220443059373d7b27443239273a22616368222c27673343273a227469 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
