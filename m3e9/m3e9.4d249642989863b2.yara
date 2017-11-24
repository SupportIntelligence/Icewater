
rule m3e9_4d249642989863b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d249642989863b2"
     cluster="m3e9.4d249642989863b2"
     cluster_size="4492"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zegost backdoor elzob"
     md5_hashes="['002e3a892092b43b9428523b4ba4f7ef','0031cdbd3b5cfbc8db0da6d046a89b78','01826b0243ae60fef31e4a536e788ea9']"

   strings:
      $hex_string = { d635444865862124be839a5eb56d95f0f95b5f56a83e3af39f13e3199dbcab271e38e754e8dd91251b7cea4e10b2bb7aa431d77f84624f72d3dbb482874d1ab1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
