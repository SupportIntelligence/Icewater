
rule m2321_59cab92dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.59cab92dc6620b32"
     cluster="m2321.59cab92dc6620b32"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys zbot backdoor"
     md5_hashes="['0ac21c47dac823b58e8de4e243d0c821','2df1dadc103172759464fda0d5751009','d924821c9f5fa6a9970cba74855d7eeb']"

   strings:
      $hex_string = { 076199ed172584644a32e69c0d70c271fe41017c2b954ff90504f9425b801ebd4b200002062dae8260acf1f5a421777636d1b4f00bc89a83e05eec448889d3d4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
