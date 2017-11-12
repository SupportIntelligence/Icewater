
rule j3e9_461665aacbab0920
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.461665aacbab0920"
     cluster="j3e9.461665aacbab0920"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bayrob ellell small"
     md5_hashes="['07038f1af9fd284f29987ff2de797538','207d304651018b4dc857de121cd68777','cfda1ccb5e6cc4cffad9c6f0d0c2316a']"

   strings:
      $hex_string = { 3b34ff424139ff4c5143ff543d3eff327248ff00f372ff52e6afff97e7e4ff72e5d5ff74e7d4ff96e8deff99e9e0ff9bebe2ff9cece6ffa5f0edffabf2efffb2 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
