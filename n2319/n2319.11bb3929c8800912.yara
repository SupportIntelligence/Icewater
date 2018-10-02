
rule n2319_11bb3929c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.11bb3929c8800912"
     cluster="n2319.11bb3929c8800912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['9eb58d054bd9909968b475c071c93bc3b2472603','9246052c02511d46b9caf7e54885fdb6617e868e','b7a5faf96a9ea1de9bf173c10b7974b85f60fb8c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.11bb3929c8800912"

   strings:
      $hex_string = { 6c656e6774687d7d293b76617220412c423d2f5e283f3a5c732a283c5b5c775c575d2b3e295b5e3e5d2a7c23285b5c772d5d2a2929242f2c433d6e2e666e2e69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
