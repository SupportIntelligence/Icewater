
rule k2321_2b9a7b30dcbbd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b9a7b30dcbbd912"
     cluster="k2321.2b9a7b30dcbbd912"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="runouce chir chinesehacker"
     md5_hashes="['20fe3649489a707d63cf114e7e9232ae','252903b9dff9f2d79ea96e8b92edc852','fa12c2536e50ba1cafcd5d9314005348']"

   strings:
      $hex_string = { 6728dd46191865ba222407b8087adba801d441ee1b34fc7f2ecc132e81e30aae8b8901df0f55fd6c258f15b2f860f5a1936d78d653fe36e03b9227fbd82ceb63 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
