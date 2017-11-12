
rule n3ed_0ca3390f1a1b5932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a1b5932"
     cluster="n3ed.0ca3390f1a1b5932"
     cluster_size="985"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['00ee26aadd7f16df5095a97c8304c304','013bece9393f53272328eaa92f3559f7','088df029d662e3bee63ec48d9cb69bc0']"

   strings:
      $hex_string = { 55576a405f4a81e200dce30381c24b594d433bcf8bea7d028bf93bfb761b568d701cff368bc5e891faffff84c059740d4383c6103bdf72ea5e5f5d5bc3686769 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
