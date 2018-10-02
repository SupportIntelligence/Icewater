
rule n26bb_2b9c909dca220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b9c909dca220b12"
     cluster="n26bb.2b9c909dca220b12"
     cluster_size="1346"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail perinet perion"
     md5_hashes="['ea7f72014fa68f25ce559f61122180461351c54f','055f6cbd5b02270b440dc39c6969d7e49f90462e','b492c9ca901d53818d87acf4b06f3cb9596c63e8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b9c909dca220b12"

   strings:
      $hex_string = { 0c26095a48c76ef902aeed4ffb3608d31c424d79d89c5e6b8997733af3019a31d128a7618f83e0c598112ffa0a9f93e435b45f0e902c60fd032de2c90d7d762e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
