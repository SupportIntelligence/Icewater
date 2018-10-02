
rule k3f8_1a2b0e669cfb5130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.1a2b0e669cfb5130"
     cluster="k3f8.1a2b0e669cfb5130"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos smsspy"
     md5_hashes="['9675beec03b57c9d375a62762ba9d1c50cc8dc4f','636e8a4eb72f1e98e21aaacf821ca42427852fb6','8c378005aeedfadbe9de9ff89de075e10c738bba']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.1a2b0e669cfb5130"

   strings:
      $hex_string = { 00402d5f313233343536373839306162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
