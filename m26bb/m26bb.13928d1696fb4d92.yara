
rule m26bb_13928d1696fb4d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13928d1696fb4d92"
     cluster="m26bb.13928d1696fb4d92"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="swisyn malicious susp"
     md5_hashes="['9158c83ac6799e212102ab03ba1db1ecb1a86330','ccbb5132eb19665aee1beabe1376a4d93a862fb4','a423035d9b68dd8f06ff1ca41edaef1e4bd274d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13928d1696fb4d92"

   strings:
      $hex_string = { eba900dadea9001c90b7001f4e62001568a5001878ba00e8f5a900fff7ad00e2eb9c00d2d2940033a2c7003192ba0046ccef00d6eb8c00d6e597002d6f71002e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
