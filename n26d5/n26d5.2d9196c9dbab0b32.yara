
rule n26d5_2d9196c9dbab0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9196c9dbab0b32"
     cluster="n26d5.2d9196c9dbab0b32"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious kryptik"
     md5_hashes="['2f4c7764e7cf1d84a698a22cd0c8ad0533951113','3da509b99e1c675f22035f987e8e927da13874d7','399daa9eb9bc4d51073283b109db61da6b375390']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9196c9dbab0b32"

   strings:
      $hex_string = { 977cc135d70adba190136018f7721f5329a59452c669d91a719e7aeaa9e7149f7094abae8d91a2f012a098b9cc63163399423f436d76f2194738cc416ab8ecda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
