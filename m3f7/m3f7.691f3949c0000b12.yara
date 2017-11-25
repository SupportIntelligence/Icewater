
rule m3f7_691f3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.691f3949c0000b12"
     cluster="m3f7.691f3949c0000b12"
     cluster_size="14"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['00d2142501525a81baaf7bbce8eaf064','193781270fba8ab4564356b1a13768cf','fc68a0572fef613e22e0eed9e91bc9cd']"

   strings:
      $hex_string = { 6e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
