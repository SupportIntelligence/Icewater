
rule n3f7_69183949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.69183949c0000b12"
     cluster="n3f7.69183949c0000b12"
     cluster_size="383"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['00a61257ee8fcbd8892d821b7eef3426','00d4a19b0acec7d1564be69967e16e16','08ad75d7a5e13a83bcf3658aa86ed1e7']"

   strings:
      $hex_string = { 46756c6c2729293b0a5f5769646765744d616e616765722e5f526567697374657257696467657428275f426c6f674172636869766556696577272c206e657720 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
