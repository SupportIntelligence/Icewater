
rule k2319_11528799c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.11528799c2200b12"
     cluster="k2319.11528799c2200b12"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6cd32237a54dc03af6775d364ecf61d147e672e2','5c475d853e1cd3418e94f886f8b427f0d340de95','7a075112f1b0bcfacc980136abfc1e3f061e53bb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.11528799c2200b12"

   strings:
      $hex_string = { 3a2830783233342c31302e384532292929627265616b7d3b7661722054325236753d7b2752304d273a226e73222c27483675273a66756e6374696f6e28512c4b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
