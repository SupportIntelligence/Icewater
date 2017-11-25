
rule k3f7_4a1ca915ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4a1ca915ca200b12"
     cluster="k3f7.4a1ca915ca200b12"
     cluster_size="55"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['02b9b4ae7491cb07165a98cc5d031a18','0755e6fbe3f6d3325abe8cd6805f7f28','44bf24ede2e54847eb6ec93e87aa53af']"

   strings:
      $hex_string = { 6e6770686f746f732e616c74657276697374612e6f7267223e484f4d453c2f613e3c2f6c693e0a3c6c692069643d226d656e752d6974656d2d31343035222063 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
