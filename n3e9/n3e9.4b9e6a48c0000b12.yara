
rule n3e9_4b9e6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b9e6a48c0000b12"
     cluster="n3e9.4b9e6a48c0000b12"
     cluster_size="1768"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre otwycal wapomi"
     md5_hashes="['003e84a97c1a59fa03c7edab15ddcdad','00544fe76230ad4b93b0963c84e003e1','040b585ef53679012929643017d444ef']"

   strings:
      $hex_string = { 1c631abdc6892acc9b66d1b00c8a8210abaead5bffed3219ddb0127be0f88d89a6fa3860b9aa576fdbce3db865ab94b278bdc5ef85514814dc30adb2a257b25e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
