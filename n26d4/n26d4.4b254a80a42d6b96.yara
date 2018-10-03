
rule n26d4_4b254a80a42d6b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.4b254a80a42d6b96"
     cluster="n26d4.4b254a80a42d6b96"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jacard delf malicious"
     md5_hashes="['02bfaf8fd81a9d03afe1e2787d0e1ee4d8a3cfbf','147ec7806ba40a7bcf985c631d11beedfb0af4fa','9036e1be01fd3a7e922cd6e64e8442fd4476e88a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.4b254a80a42d6b96"

   strings:
      $hex_string = { b44580ad41b287848107ce6c3c210b8aa5e7dbde6dd977eea4c586e83501663dbe132a4cc37f676e55294d231aa792e66122ab085d3ee3b0d5cc9ba3d1e94e06 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
