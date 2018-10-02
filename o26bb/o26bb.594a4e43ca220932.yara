
rule o26bb_594a4e43ca220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a4e43ca220932"
     cluster="o26bb.594a4e43ca220932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply filerepmetagen heuristic"
     md5_hashes="['a05adb4301da98c4b9382f03068c3e38e36add22','add531603a0618230920dba8ebb4b850c5f3a8a7','320170109eda0fa831bb77d7cfec4e574d06cb99']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a4e43ca220932"

   strings:
      $hex_string = { 55544638537472696e67e9fd0200fc2340000a0d52617742797465537472696e67ffff020000142440001408504c6f6e67496e749c1040000200282440001405 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
