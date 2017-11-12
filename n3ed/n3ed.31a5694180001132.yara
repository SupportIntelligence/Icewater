
rule n3ed_31a5694180001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a5694180001132"
     cluster="n3ed.31a5694180001132"
     cluster_size="73"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['17da22352a4bc8362cb741a0082f6742','186f2812019aa4872a65a06bbd16ed56','b363259a9f08978c09cba0d1315c4023']"

   strings:
      $hex_string = { 1100ff08b001eb232bc203c02bf23bc67d178d0c510fb714410fb75c4102c1e2100bd340891740ebb632c05f5e5b5dc38a4424048ac880e96180f919770204e0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
