
rule m3e9_13665ec144000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13665ec144000916"
     cluster="m3e9.13665ec144000916"
     cluster_size="77"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted dealply"
     md5_hashes="['06daf39bfda1b21dd8e6599922141a5f','086b8dc89b072816db30d8fc2e844ce9','4011561f6f2b9a7a68c56ca493d3da2d']"

   strings:
      $hex_string = { 3352e3b778f62a76ccb26c3d72c7a8b1d28b0b94b6dff016cffa7a6bd7939b543b9745f2d305068f8af9adc1b5a442af63f5e55e206f74c26a6ee90c37ed2986 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
