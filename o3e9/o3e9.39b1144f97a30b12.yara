
rule o3e9_39b1144f97a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.39b1144f97a30b12"
     cluster="o3e9.39b1144f97a30b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious badfile"
     md5_hashes="['486b5edd60998b949e4dae92e66cb988','5778e0b60870e9635f3734e24a81aad4','de3d37a471bfedcc7af75ef36eaf7697']"

   strings:
      $hex_string = { bb7883fa9d0a91cbf212f644e8d972210f654931dce2ccc7b37492ddaf77f5342807a4e3fb84b6267b20b0ae3637157ee175082e053862f3b85fb1e6a1e05b79 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
