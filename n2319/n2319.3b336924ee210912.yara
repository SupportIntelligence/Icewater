
rule n2319_3b336924ee210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.3b336924ee210912"
     cluster="n2319.3b336924ee210912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery classic expkit"
     md5_hashes="['dc8f15f3ee7db07b7f20365e4408dbf6008a1daa','540d3e816ef553477569879e9029e2b2d6ebb74e','687b2f1c8c3f6108de748f44b274dffa6222b588']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.3b336924ee210912"

   strings:
      $hex_string = { 50776151657546526932702f335362364543354c335143785a42674141414f436f724c57317a4d6e363554726c6b48344e635637514e6355517437476e374b49 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
