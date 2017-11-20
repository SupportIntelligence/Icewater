
rule k3ec_403c1ae9e6b46b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.403c1ae9e6b46b32"
     cluster="k3ec.403c1ae9e6b46b32"
     cluster_size="93"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector airyvoki malicious"
     md5_hashes="['077609a5a788522c706d870cb99b0f3e','07e3dae94e7a6c16ab254fccb1d0b6fa','398b30c2a0a6b2f67f7382a50c8e4c55']"

   strings:
      $hex_string = { 180305be15cd5b07088bf181c6f8d959070b8bf1c1e60481c6459b3c070702038b4500048bd58b0207020233c6058bf833fe97090203894500068bfd8bd08917 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
