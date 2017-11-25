
rule m3f7_699d91a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.699d91a1c2000b32"
     cluster="m3f7.699d91a1c2000b32"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker html"
     md5_hashes="['12a8a546211d580e350e0e4da87d99bf','499b0a721459adaee9845f1ba13c0674','d78e803e8de4e1ca02da84e697f8690a']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c656674 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
