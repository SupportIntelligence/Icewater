
rule o3e9_1ad308d69e927916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1ad308d69e927916"
     cluster="o3e9.1ad308d69e927916"
     cluster_size="325"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['0005eba20e8a13ee0af7588b08503214','00b263e4ee33c9f443666956a9308842','0be9897074cf7e9c37a364c8fee366ba']"

   strings:
      $hex_string = { af49dc97dfdd49dfb85ec4a65c48da878850c47f8e1c8458504ec235305d61dc2e109ac5e953117c3c195cacedf2b9ca4c8e4d0f9192509af01ef3d194b08af5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
