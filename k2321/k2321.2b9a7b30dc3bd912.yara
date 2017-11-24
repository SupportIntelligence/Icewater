
rule k2321_2b9a7b30dc3bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b9a7b30dc3bd912"
     cluster="k2321.2b9a7b30dc3bd912"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="runouce chir chinesehacker"
     md5_hashes="['0196796160cafc1aafd2eb46bda0605f','27234a507b477621ae978c7dbcb96f0f','fbf7ff63a24de2fa444385225786600e']"

   strings:
      $hex_string = { 6728dd46191865ba222407b8087adba801d441ee1b34fc7f2ecc132e81e30aae8b8901df0f55fd6c258f15b2f860f5a1936d78d653fe36e03b9227fbd82ceb63 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
