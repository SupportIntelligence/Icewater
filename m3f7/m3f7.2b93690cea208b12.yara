
rule m3f7_2b93690cea208b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b93690cea208b12"
     cluster="m3f7.2b93690cea208b12"
     cluster_size="51"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['033399e2a45019c941eddcf091e8ab8f','0b25e1c5826989ccd2121d5e2f168e09','4dfa25d94f860345f37a7479433f868f']"

   strings:
      $hex_string = { 46756c6c2729293b0a5f5769646765744d616e616765722e5f526567697374657257696467657428275f426c6f674172636869766556696577272c206e657720 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
