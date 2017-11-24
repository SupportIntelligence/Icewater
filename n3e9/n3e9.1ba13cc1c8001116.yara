
rule n3e9_1ba13cc1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba13cc1c8001116"
     cluster="n3e9.1ba13cc1c8001116"
     cluster_size="140"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun vilsel"
     md5_hashes="['0f67a6b9cffb1e0d6f379d9e62c523a4','0f97e067fffd42d742a4c41dc6a6b1c8','6c9a186512ee81a6febb376832486234']"

   strings:
      $hex_string = { c8d165d2a969648e940896fd9c55e5d7389575cdf5f90f9d74360d5f5e862721c0611e6f58d847b9c3044c88b64bd4bd721b89a1b7cc14436f62ab4d03a30225 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
