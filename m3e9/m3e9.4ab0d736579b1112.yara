
rule m3e9_4ab0d736579b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4ab0d736579b1112"
     cluster="m3e9.4ab0d736579b1112"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik malicious"
     md5_hashes="['485b0e1f0fc2f8eaf647692ff108185f','7ddc61007b287283ce6d76c1bc51c48f','f19a9c5d303f0673e37ec7de9253fde8']"

   strings:
      $hex_string = { 66676e5f6e59556f987a726f6d7990a2dcf9fffdfff7f7b7000000f8ffff0312282c20101111101a585765736c30667a635f5c75b3a79cc0cecdaea9aae6f2fa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
