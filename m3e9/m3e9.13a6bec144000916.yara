
rule m3e9_13a6bec144000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13a6bec144000916"
     cluster="m3e9.13a6bec144000916"
     cluster_size="451"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['0148b107e3e3ee27aaaf87fc4da793d9','015669a4373db5e049e84806d6c0b902','09d03796aa729e6846f29d978545d588']"

   strings:
      $hex_string = { 00f52e085692383ccfa9e3370d5055d78c3b55318f8da4d4b346dba41891a14982cc60671f9e12bd25750a4249f61ee72fe29f720c0faa473be93b51b27d7653 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
