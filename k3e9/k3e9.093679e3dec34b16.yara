
rule k3e9_093679e3dec34b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.093679e3dec34b16"
     cluster="k3e9.093679e3dec34b16"
     cluster_size="84"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unwanted installcore advml"
     md5_hashes="['00e02f8c334aa70200ed2c6f57b1768f','00ed6c5ded785a6312d82bb64a20efed','3d9dffd2d7ff3164e89ebb2c0ad8d0d0']"

   strings:
      $hex_string = { 4449d5dab6b432b28319d36d3fdeec783bb88fa95e6ac9f8e9020716aaa404b0fd9671f3dbbe31e04e00981a24c623e13a4635850343a5a01d5b3454f2a68e7e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
