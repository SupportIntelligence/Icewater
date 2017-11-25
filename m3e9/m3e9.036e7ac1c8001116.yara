
rule m3e9_036e7ac1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.036e7ac1c8001116"
     cluster="m3e9.036e7ac1c8001116"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted riskware"
     md5_hashes="['026ffdaec84ab8c1a432423ed1f58f3a','07b6703d6aac0eafae70dcbaa17055ce','9908c226d2948900485de4d0014089f4']"

   strings:
      $hex_string = { bbdb5a88225db9ed7e82659012b1d38b3dbfe41ffc3677e67050a88df6043c61bc13aa67109aee5f8ca72a73e5362f5ee7ba694042b59b86c4309f7c47665559 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
