
rule n3e9_199d6949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.199d6949c0000b12"
     cluster="n3e9.199d6949c0000b12"
     cluster_size="54"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt manbat injector"
     md5_hashes="['05345841a7426e47550f315594dc4319','05a2ba81a3f8becc7a55c0d042485fa0','3a7dd9ee87157bea714598da42575b9b']"

   strings:
      $hex_string = { 03d8109895c93cb1381871c524c4c7f4d6d7a470aee4050c727c9d899f9bb21c1ae7cd60904c6d80333d5e488b8e2c261b57813a8af7c1bd2d73de675f6279bf }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
