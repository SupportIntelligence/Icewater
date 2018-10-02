
rule k2319_3105c82dea208912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3105c82dea208912"
     cluster="k2319.3105c82dea208912"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['e9691808ee09c007ac05b0fcd736f21afca5f119','88975910db3ce3846a1ea9a63c7d4cd394a1f88d','7665f1a7426e55afc369497b906b76cbbd2456ac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3105c82dea208912"

   strings:
      $hex_string = { 62312b6c342b4c39292c285530295d2c6765743a66756e6374696f6e2857297b76617220433d2265746368223b766172204f373d746869735b286e3850304c2e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
