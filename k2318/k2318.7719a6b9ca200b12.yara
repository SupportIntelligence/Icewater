
rule k2318_7719a6b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.7719a6b9ca200b12"
     cluster="k2318.7719a6b9ca200b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['c2db84f20e0664f5a9105479d420d9abe2178e39','68c8be7a3156d6c55e7379940d227557a3f740b1','2abe5f32617c2a3b7bde9a0f8312a70e2450432f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.7719a6b9ca200b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
