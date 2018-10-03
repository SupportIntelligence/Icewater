
rule n26c0_549e859da2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.549e859da2210b32"
     cluster="n26c0.549e859da2210b32"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut virtob malicious"
     md5_hashes="['5bdd4bf684f7d24f3df4f8347b16bc8b29252e8b','76adad9e5379b48ff35e07b50a4d064c57e54028','ddfc651102aab8ad929a4718aa82640a76ef6792']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.549e859da2210b32"

   strings:
      $hex_string = { 8b5dfc53e826ac04008945f885c0752da1045007013bc6741ff6401c0474198078190272135368941a00016a2bff7014ff7010e8ad3000006a085feb66837d0c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
