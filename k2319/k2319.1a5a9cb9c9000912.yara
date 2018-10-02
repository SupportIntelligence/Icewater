
rule k2319_1a5a9cb9c9000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5a9cb9c9000912"
     cluster="k2319.1a5a9cb9c9000912"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['15bed628abcbf607962bec4de385bc526b0fa212','a1c477397e837d47cd055fd3f6dc246cad151cfc','e207e4b02b37657418d0e0126bcc2247fadeae7a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5a9cb9c9000912"

   strings:
      $hex_string = { 28322e343045312c3078323332292929627265616b7d3b7661722053394139693d7b27753952273a224a222c274f3869273a66756e6374696f6e28712c43297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
