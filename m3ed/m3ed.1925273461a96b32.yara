
rule m3ed_1925273461a96b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.1925273461a96b32"
     cluster="m3ed.1925273461a96b32"
     cluster_size="70"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['018d6239322622fb73ea1de1b284c0a5','0225e7d4a3bb9e93cc42613b9c965d85','13570007288aaab93636c436e9aef91c']"

   strings:
      $hex_string = { 6119530a4481ce5d9f54a610de770da482d4d2934cab118d50adf02b1e14ede2c3644e264c84d768ccd071a0c8c558c6d5a1594f41af5ee72e83377eae21aa28 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
